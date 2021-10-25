#include <atomic>
#include <list>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/time/time.h"
#include "file/epoll.h"
#include "file/filesystem.h"
#include "gflags/gflags.h"
#include "glog/logging.h"
#include "main/common/message.h"
#include "main/common/thread_manager.h"
#include "net/net.h"
#include "nlohmann/json.hpp"
#include "utils/status_macros.h"

DECLARE_bool(logtostderr);

DEFINE_string(listen_manage_sock, "",
              "The domain sock path which is used to communicate with web");

DEFINE_uint32(listen_net_port, 0,
              "The tcp port used to communicate with clients");

namespace {

using namespace std::placeholders;
using ::common::ThreadManager;
using ::nlohmann::json;

constexpr absl::string_view kManageThreadName = "manage";
constexpr absl::string_view kTcpForwardListenThreadName = "tcp_forward_listen";
constexpr absl::string_view kTimeoutCheckThreadName = "timeout_check";
constexpr absl::string_view kListenThreadName = "listen";
constexpr absl::string_view kClientThreadName = "client";
constexpr absl::string_view kClientForwardThreadName = "client_forward";

constexpr absl::string_view kManageCommandConfig = "CONFIG";
constexpr absl::string_view kManageCommandConfigOK = "CONFIG_OK";

struct Config {
    struct Client {
        std::string id;
        std::string key;
    };
    struct TcpForward {
        std::string client_id;
        uint16_t listen_port;
        std::string forward_client_ip;
        uint16_t forward_client_port;
    };

    std::vector<Client> clients;
    std::vector<TcpForward> tcp_forwards;
};

absl::StatusOr<Config> ParseConfig(absl::string_view data) {
    const json j = json::parse(data);
    Config config;

    if (j.find("clients") == j.end()) {
        return absl::InvalidArgumentError(
            "The config does not have `clients`.");
    }
    if (!j.at("clients").is_array()) {
        return absl::InvalidArgumentError(
            "The `clients` in config is not an array.");
    }
    for (const auto& c : j.at("clients")) {
        if (!c.is_object()) {
            return absl::InvalidArgumentError(
                "The element in `clients` is not an object.");
        }
        for (const auto& key : {"id", "key"}) {
            if (c.find(key) == c.end()) {
                return absl::InvalidArgumentError(absl::StrFormat(
                    "The element in `clients` does not have `%s`.", key));
            }
        }
        config.clients.push_back({
            .id = c.at("id").get<std::string>(),
            .key = c.at("key").get<std::string>(),
        });
    }

    if (j.find("tcp_forwards") == j.end()) {
        return absl::InvalidArgumentError(
            "The config does not have `tcp_forwards`.");
    }
    if (!j.at("tcp_forwards").is_array()) {
        return absl::InvalidArgumentError(
            "The `tcp_forwards` in config is not an array.");
    }
    for (const auto& t : j.at("tcp_forwards")) {
        if (!t.is_object()) {
            return absl::InvalidArgumentError(
                "The element in `tcp_forwards` is not an object.");
        }
        for (const auto& key : {"client_id", "listen_port", "forward_client_ip",
                                "forward_client_port"}) {
            if (t.find(key) == t.end()) {
                return absl::InvalidArgumentError(absl::StrFormat(
                    "The element in `tcp_forwards` does not have `%s`.", key));
            }
        }
        config.tcp_forwards.push_back({
            .client_id = t.at("client_id").get<std::string>(),
            .listen_port = t.at("listen_port").get<uint16_t>(),
            .forward_client_ip = t.at("forward_client_ip").get<std::string>(),
            .forward_client_port = t.at("forward_client_port").get<uint16_t>(),
        });
    }

    std::set<std::string> client_ids;
    for (const auto& c : config.clients) {
        if (client_ids.find(c.id) != client_ids.end()) {
            return absl::InvalidArgumentError(
                absl::StrFormat("Dup client id `%s`.", c.id));
        }
        client_ids.insert(c.id);
    }

    std::set<uint16_t> listen_ports;
    for (const auto& t : config.tcp_forwards) {
        if (listen_ports.find(t.listen_port) != listen_ports.end()) {
            return absl::InvalidArgumentError(
                absl::StrFormat("Dup listen port `%d`.", t.listen_port));
        }
        listen_ports.insert(t.listen_port);
        if (client_ids.find(t.client_id) == client_ids.end()) {
            return absl::InvalidArgumentError(absl::StrFormat(
                "Cannot find client with id `%s`.", t.client_id));
        }
    }

    return config;
}

class Server {
   public:
    Server() { ended_ = 1; }

    absl::Status ManageMain(uint64_t tid, ThreadManager* tm) {
        RETURN_IF_ERROR(tm->SetThreadName(tid, kManageThreadName));

        // listen domain sock
        ASSIGN_OR_RETURN(auto server, net::Socket(AF_UNIX, SOCK_STREAM, 0));
        RETURN_IF_ERROR(server->SetReuseAddr());
        ASSIGN_OR_RETURN(auto listen_addr,
                         net::SocketAddr::NewUnix(FLAGS_listen_manage_sock));
        file::Unlink(FLAGS_listen_manage_sock).IgnoreError();
        RETURN_IF_ERROR(server->Bind(listen_addr));
        RETURN_IF_ERROR(server->Listen(1024));

        while (true) {
            if (ended_.load()) {
                std::lock_guard<std::mutex> lock(mtx_);
                ended_.store(0);

                // 变量初始化
                tcp_incommings_.clear();

                // 启动其他线程
                tm->Launch(
                    std::bind(&Server::TimeoutCheckThread, this, _1, _2));
                tm->Launch(std::bind(&Server::ListenThread, this, _1, _2));
                for (const auto& tcp : config_.tcp_forwards) {
                    tm->Launch(std::bind(&Server::TcpForwardListenThread, this,
                                         _1, _2, tcp));
                }
            }

            // accept new socket
            ASSIGN_OR_RETURN(auto socket, server->Accept());

            // manage一定是一问一答的形式，每次一行
            while (true) {
                // readline
                std::string line;
                while (true) {
                    ASSIGN_OR_RETURN(std::string chunk, socket->Read(1024));
                    if (chunk.empty()) {
                        break;
                    }
                    absl::StrAppend(&line, chunk);
                    if (chunk.find('\n') != chunk.npos) {
                        break;
                    }
                }
                if (line.empty()) {
                    break;
                }
                LOG(INFO) << "manage line : " << line;

                // 分析
                absl::string_view line_view = line;
                absl::string_view command;
                absl::string_view command_data;

                while (!line_view.empty() &&
                       std::isspace(*line_view.rbegin())) {
                    line_view.remove_suffix(1);
                }

                if (size_t space_pos = line_view.find(' ');
                    space_pos != line_view.npos) {
                    command = line_view.substr(0, space_pos);
                    command_data = line_view.substr(space_pos + 1);
                } else {
                    command = line_view;
                }

                // CONFIG
                if (command == kManageCommandConfig) {
                    auto config = ParseConfig(command_data);
                    if (config.ok()) {
                        // 先结束其他线程
                        ended_.store(1);
                        RETURN_IF_ERROR(tm->WaitOnlyThreadsAlive(
                            {std::string(kManageThreadName)}));
                        // 在下一次循环，会检查ended_并启动其他线程

                        std::lock_guard<std::mutex> lock(mtx_);
                        config_ = *config;
                        RETURN_IF_ERROR(socket->Write(kManageCommandConfigOK));
                    } else {
                        RETURN_IF_ERROR(socket->Write(absl::StrFormat(
                            "ERR %s", config.status().ToString())));
                    }
                }
            }
        }

        return absl::OkStatus();
    }
    void ManageThread(uint64_t tid, ThreadManager* tm) {
        try {
            auto status = ManageMain(tid, tm);
            if (!status.ok()) {
                LOG(ERROR) << "manage thread error : " << status;
                exit(1);
            } else {
                LOG(INFO) << "manage thread exit";
            }
        } catch (...) {
            LOG(ERROR) << "manage thread catched an error";
        }
        exit(0);
    }

    absl::Status TcpForwardListenMain(uint64_t tid, ThreadManager* tm,
                                      Config::TcpForward tcp_forward) {
        RETURN_IF_ERROR(tm->SetThreadName(
            tid,
            absl::StrFormat("%s_%s_%d", kTcpForwardListenThreadName,
                            tcp_forward.client_id, tcp_forward.listen_port)));

        // listen sock
        ASSIGN_OR_RETURN(auto server, net::Socket(AF_INET, SOCK_STREAM, 0));
        RETURN_IF_ERROR(server->SetReuseAddr());
        ASSIGN_OR_RETURN(
            auto listen_addr,
            net::SocketAddr::NewIPv4("0.0.0.0", tcp_forward.listen_port));
        RETURN_IF_ERROR(server->Bind(listen_addr));
        RETURN_IF_ERROR(server->Listen(1024));

        ASSIGN_OR_RETURN(auto epoll, file::EPoll::Create());
        RETURN_IF_ERROR(epoll->Add(server.get(), EPOLLIN));

        while (true) {
            // wait event
            absl::Duration timeout = absl::Milliseconds(100);
            ASSIGN_OR_RETURN(auto events, epoll->Wait(1024, &timeout));
            if (ended_.load()) {
                break;
            }
            if (events.empty()) {
                continue;
            }

            // accept new socket
            ASSIGN_OR_RETURN(auto socket, server->Accept());

            {
                std::lock_guard<std::mutex> lock(mtx_);
                tcp_incommings_.push_back({.socket = std::move(socket),
                                           .created_time = absl::Now(),
                                           .tcp_forward = tcp_forward,
                                           .have_sent_to_client = false});
            }
        }

        return absl::OkStatus();
    }
    void TcpForwardListenThread(uint64_t tid, ThreadManager* tm,
                                Config::TcpForward tcp_forward) {
        try {
            auto status = TcpForwardListenMain(tid, tm, tcp_forward);
            if (!status.ok()) {
                LOG(ERROR) << "tcp forward thread error : " << status;
                exit(1);
            } else {
                LOG(INFO) << "tcp forward thread exit";
            }
        } catch (...) {
            LOG(ERROR) << "tcp forward thread catched an error";
        }
    }

    absl::Status TimeoutCheckMain(uint64_t tid, ThreadManager* tm) {
        RETURN_IF_ERROR(tm->SetThreadName(tid, kTimeoutCheckThreadName));

        while (true) {
            absl::SleepFor(absl::Milliseconds(100));
            if (ended_.load()) {
                break;
            }

            {
                std::lock_guard<std::mutex> lock(mtx_);
                auto it = tcp_incommings_.begin();
                while (it != tcp_incommings_.end()) {
                    if (absl::Now() - it->created_time > absl::Seconds(60)) {
                        it = tcp_incommings_.erase(it);
                    } else {
                        it++;
                    }
                }
            }
        }

        return absl::OkStatus();
    }
    void TimeoutCheckThread(uint64_t tid, ThreadManager* tm) {
        try {
            auto status = TimeoutCheckMain(tid, tm);
            if (!status.ok()) {
                LOG(ERROR) << "timeout check thread error : " << status;
                exit(1);
            } else {
                LOG(INFO) << "timeout check thread exit";
            }
        } catch (...) {
            LOG(ERROR) << "timeout check thread catched an error";
        }
    }

    absl::Status ListenMain(uint64_t tid, ThreadManager* tm) {
        RETURN_IF_ERROR(tm->SetThreadName(tid, kListenThreadName));

        // listen sock
        ASSIGN_OR_RETURN(auto server, net::Socket(AF_INET, SOCK_STREAM, 0));
        RETURN_IF_ERROR(server->SetReuseAddr());
        ASSIGN_OR_RETURN(
            auto listen_addr,
            net::SocketAddr::NewIPv4("0.0.0.0", FLAGS_listen_net_port));
        RETURN_IF_ERROR(server->Bind(listen_addr));
        RETURN_IF_ERROR(server->Listen(1024));

        ASSIGN_OR_RETURN(auto epoll, file::EPoll::Create());
        RETURN_IF_ERROR(epoll->Add(server.get(), EPOLLIN));

        while (true) {
            // wait event
            absl::Duration timeout = absl::Milliseconds(100);
            ASSIGN_OR_RETURN(auto events, epoll->Wait(1024, &timeout));
            if (ended_.load()) {
                break;
            }
            if (events.empty()) {
                continue;
            }

            // accept new socket
            ASSIGN_OR_RETURN(auto socket, server->Accept());

            tm->Launch(std::bind(&Server::ClientSocketThread, this, _1, _2,
                                 socket.release()));
        }

        return absl::OkStatus();
    }
    void ListenThread(uint64_t tid, ThreadManager* tm) {
        try {
            auto status = ListenMain(tid, tm);
            if (!status.ok()) {
                LOG(ERROR) << "listen thread error : " << status;
                exit(1);
            } else {
                LOG(INFO) << "listen thread exit";
            }
        } catch (...) {
            LOG(ERROR) << "listen thread catched an error";
        }
    }

    absl::Status ClientSocketMain(uint64_t tid, ThreadManager* tm,
                                  std::unique_ptr<net::NetSocket> socket) {
        // client的连接有两种情况：
        // 1. 普通的控制线程
        // 2. tcp转发线程

        enum Status {
            UNKNOWN_ID_KEY,
            WAIT_FIRST_MESSAGE,
            NORMAL_CLIENT,
            TCP_FORWARD
        };
        Status status = UNKNOWN_ID_KEY;
        std::string id;
        std::string key;

        ASSIGN_OR_RETURN(auto epoll, file::EPoll::Create());
        RETURN_IF_ERROR(epoll->Add(socket.get(), EPOLLIN));

        std::string socket_data;
        std::unique_ptr<net::NetSocket> tcp_forward_socket;
        std::string tcp_forward_socket_data;
        while (true) {
            absl::Duration timeout = absl::Milliseconds(100);
            ASSIGN_OR_RETURN(auto events, epoll->Wait(1024, &timeout));
            if (ended_.load()) {
                break;
            }
            if (status == NORMAL_CLIENT) {
                absl::optional<proto::TcpForward> send_forward = absl::nullopt;
                {
                    std::lock_guard<std::mutex> lock(mtx_);
                    for (auto& tcp_forward : tcp_incommings_) {
                        if (!tcp_forward.have_sent_to_client &&
                            tcp_forward.tcp_forward.client_id == id) {
                            tcp_forward.have_sent_to_client = true;

                            proto::TcpForward tmp;
                            ASSIGN_OR_RETURN(
                                *tmp.mutable_remote_ip(),
                                tcp_forward.socket->remote_addr().ip());
                            ASSIGN_OR_RETURN(
                                auto remote_port,
                                tcp_forward.socket->remote_addr().port());
                            tmp.set_remote_port(remote_port);
                            ASSIGN_OR_RETURN(
                                *tmp.mutable_accepted_ip(),
                                tcp_forward.socket->local_addr().ip());
                            ASSIGN_OR_RETURN(
                                auto accepted_port,
                                tcp_forward.socket->local_addr().port());
                            tmp.set_accepted_port(accepted_port);
                            tmp.set_to_ip(
                                tcp_forward.tcp_forward.forward_client_ip);
                            tmp.set_to_port(
                                tcp_forward.tcp_forward.forward_client_port);
                            send_forward = tmp;

                            break;
                        }
                    }
                }
                if (send_forward.has_value()) {
                    proto::Content content;
                    *content.mutable_new_tcp_forward() = *send_forward;
                    ASSIGN_OR_RETURN(auto send_data, common::message::Serialize(
                                                         id, key, content));
                    RETURN_IF_ERROR(socket->WriteAll(send_data));
                }
            }

            if (events.empty()) {
                continue;
            }

            // read data from sockets
            for (const auto& event : events) {
                if (event.file->fd() == socket->fd()) {
                    ASSIGN_OR_RETURN(std::string data, socket->Read(1024));
                    if (data.empty()) {
                        // client socket closed
                        return absl::OkStatus();
                    }
                    absl::StrAppend(&socket_data, data);
                } else if (tcp_forward_socket &&
                           event.file->fd() == tcp_forward_socket->fd()) {
                    ASSIGN_OR_RETURN(std::string data,
                                     tcp_forward_socket->Read(1024));
                    if (data.empty()) {
                        // socket closed
                        return absl::OkStatus();
                    }
                    absl::StrAppend(&tcp_forward_socket_data, data);
                }
            }

            if (status == UNKNOWN_ID_KEY) {
                ASSIGN_OR_RETURN(auto socket_id,
                                 common::message::TryParseID(socket_data));
                if (!socket_id.has_value()) {
                    continue;
                }

                {  // find client id & key
                    std::lock_guard<std::mutex> lock(mtx_);
                    for (const auto& client : config_.clients) {
                        if (*socket_id == client.id) {
                            id = client.id;
                            key = client.key;
                        }
                    }
                }

                if (id.empty()) {
                    RETURN_IF_ERROR(socket->WriteAll("ERR Cannot found id.\n"));
                    return absl::InternalError(absl::StrFormat(
                        "ERR Cannot found id `%s`", *socket_id));
                }

                status = WAIT_FIRST_MESSAGE;
            }

            if (status == WAIT_FIRST_MESSAGE) {
                uint64_t consumed_length;
                ASSIGN_OR_RETURN(auto content,
                                 common::message::TryParse(id, key, socket_data,
                                                           &consumed_length));
                if (!content.has_value()) {
                    continue;
                }
                socket_data = socket_data.substr(consumed_length);

                if (content->has_ping()) {
                    // 这是一个普通client
                    RETURN_IF_ERROR(tm->SetThreadName(
                        tid, absl::StrFormat("%s_%s", kClientThreadName, id)));
                    LOG(INFO) << "New ping : " << content->DebugString();
                    status = NORMAL_CLIENT;
                } else if (content->has_accept_tcp_forward()) {
                    // 这是一个TCP转发
                    std::lock_guard<std::mutex> lock(mtx_);
                    absl::optional<TcpForwardIncomming> tcp_incomming =
                        absl::nullopt;
                    for (auto it = tcp_incommings_.begin();
                         it != tcp_incommings_.end(); it++) {
                        if (it->tcp_forward.client_id != id) continue;
                        if (*it->socket->remote_addr().ip() !=
                            content->accept_tcp_forward().remote_ip())
                            continue;
                        if (*it->socket->remote_addr().port() !=
                            content->accept_tcp_forward().remote_port())
                            continue;
                        tcp_incomming = std::move(*it);
                        tcp_incommings_.erase(it);
                        break;
                    }
                    if (!tcp_incomming.has_value()) {
                        RETURN_IF_ERROR(
                            socket->WriteAll("Cannot find tcp forward"));
                        return absl::InternalError("Cannot find tcp forward");
                    }
                    RETURN_IF_ERROR(tm->SetThreadName(
                        tid, absl::StrFormat("%s_%s", kClientForwardThreadName,
                                             id)));
                    tcp_forward_socket = std::move(tcp_incomming->socket);
                    RETURN_IF_ERROR(
                        epoll->Add(tcp_forward_socket.get(), EPOLLIN));
                    status = TCP_FORWARD;
                } else {
                    RETURN_IF_ERROR(
                        socket->WriteAll("Unsupported first message"));
                    return absl::InternalError(
                        absl::StrFormat("Unsupported first message : %s",
                                        content->DebugString()));
                }
            }

            if (status == NORMAL_CLIENT) {
                // nothing
            }

            if (status == TCP_FORWARD) {
                while (true) {
                    uint64_t consumed_length;
                    ASSIGN_OR_RETURN(auto content, common::message::TryParse(
                                                       id, key, socket_data,
                                                       &consumed_length));
                    if (!content.has_value()) {
                        break;
                    }
                    socket_data = socket_data.substr(consumed_length);

                    if (!content->has_tcp_packet()) {
                        RETURN_IF_ERROR(
                            socket->WriteAll("Only need tcp packet"));
                        return absl::InternalError(
                            absl::StrFormat("Only need tcp packet : %s",
                                            content->DebugString()));
                    }

                    RETURN_IF_ERROR(tcp_forward_socket->WriteAll(
                        content->tcp_packet().data()));
                }

                if (!tcp_forward_socket_data.empty()) {
                    proto::TcpPacket packet;
                    *packet.mutable_data() = tcp_forward_socket_data;
                    tcp_forward_socket_data.clear();
                    proto::Content content;
                    *content.mutable_tcp_packet() = packet;
                    ASSIGN_OR_RETURN(
                        std::string send_data,
                        common::message::Serialize(id, key, content));
                    RETURN_IF_ERROR(socket->WriteAll(send_data));
                }
            }
        }

        return absl::OkStatus();
    }
    void ClientSocketThread(uint64_t tid, ThreadManager* tm,
                            net::NetSocket* socket) {
        try {
            auto status = ClientSocketMain(
                tid, tm, std::unique_ptr<net::NetSocket>(socket));
            if (!status.ok()) {
                LOG(ERROR) << "client socket thread error : " << status;
            } else {
                LOG(INFO) << "client socket thread exit";
            }
        } catch (...) {
            LOG(ERROR) << "client socket thread catched an error";
        }
    }

   private:
    struct TcpForwardIncomming {
        std::unique_ptr<net::NetSocket> socket;
        absl::Time created_time;
        Config::TcpForward tcp_forward;
        bool have_sent_to_client;
    };

    std::atomic_int ended_;
    std::mutex mtx_;

    // 以下数据的读和写需要使用mtx_进行保护
    Config config_;
    std::list<TcpForwardIncomming> tcp_incommings_;
};

}  // namespace

int main(int argc, char* argv[]) {
    FLAGS_logtostderr = true;
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    google::InitGoogleLogging(argv[0]);

    if (FLAGS_listen_manage_sock.empty()) {
        LOG(ERROR) << "--listen_manage_sock is required";
        return 1;
    }
    if (FLAGS_listen_net_port == 0) {
        LOG(ERROR) << "--listen_net_port is required";
        return 1;
    }

    LOG(INFO) << "Server started";

    Server server;
    ThreadManager tm;

    tm.Launch(std::bind(&Server::ManageThread, &server, _1, _2));

    tm.Start();

    return 0;
}
