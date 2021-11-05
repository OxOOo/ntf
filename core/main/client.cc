#include <set>
#include <string>
#include <vector>

#include "absl/strings/str_format.h"
#include "absl/time/time.h"
#include "file/epoll.h"
#include "file/filesystem.h"
#include "file/nonblocking.h"
#include "gflags/gflags.h"
#include "glog/logging.h"
#include "main/common/message.h"
#include "main/common/thread_manager.h"
#include "main/proto/message.pb.h"
#include "net/net.h"
#include "utils/status_macros.h"

DECLARE_bool(logtostderr);

DEFINE_string(server, "", "Server IPv4 address");

DEFINE_uint32(port, 0, "Server port");

DEFINE_string(id, "", "Client ID");

DEFINE_string(key, "", "Client key");

namespace {

using namespace std::placeholders;
using ::common::ThreadManager;

constexpr absl::string_view kMainThreadName = "main";
constexpr absl::string_view kTcpForwardThreadName = "tcp_forward";

class Client {
   public:
    absl::Status Main(uint64_t tid, ThreadManager* tm) {
        RETURN_IF_ERROR(tm->SetThreadName(tid, kMainThreadName));

        std::string id = FLAGS_id;
        std::string key = FLAGS_key;
        absl::Time last_received_heartbeat = absl::Now();
        absl::Time last_sent_heartbeat = absl::Now();

        ASSIGN_OR_RETURN(auto socket, net::Socket(AF_INET, SOCK_STREAM, 0));
        ASSIGN_OR_RETURN(auto server_addr,
                         net::SocketAddr::NewIPv4(FLAGS_server, FLAGS_port));
        RETURN_IF_ERROR(socket->Connect(server_addr));
        RETURN_IF_ERROR(socket->SetSockOpt<int>(SOL_SOCKET, SO_KEEPALIVE, 1));

        ASSIGN_OR_RETURN(auto socket_io,
                         file::NonblockingIO::Create(std::move(socket)));
        ASSIGN_OR_RETURN(auto epoll, file::EPoll::Create());

        {  // ping
            proto::Ping ping;
            ping.set_message("hello world");
            proto::Content content;
            *content.mutable_ping() = ping;
            ASSIGN_OR_RETURN(std::string data,
                             common::message::Serialize(id, key, content));
            socket_io->AppendWriteData(data);
        }

        while (true) {
            if (absl::Now() - last_received_heartbeat > absl::Seconds(60)) {
                LOG(INFO) << "Heartbeat timeout";
                break;
            }

            RETURN_IF_ERROR(epoll->DeleteIfExists(socket_io->file()));
            if (socket_io->HasDataToWrite()) {
                RETURN_IF_ERROR(epoll->Add(socket_io->file(), EPOLLOUT));
            } else {
                RETURN_IF_ERROR(epoll->Add(socket_io->file(), EPOLLIN));
            }

            absl::Duration timeout = absl::Milliseconds(100);
            ASSIGN_OR_RETURN(auto events, epoll->Wait(1024, &timeout));
            for (const auto& event : events) {
                if (event.file->fd() == socket_io->file()->fd()) {
                    if (event.events & EPOLLIN) {
                        ASSIGN_OR_RETURN(auto read_bytes,
                                         socket_io->TryReadOnce(1024));
                        // 如果可以读数据但是并没有任何数据，那么表示closed
                        if (read_bytes == 0) {
                            return absl::InternalError("Socket closed");
                        }
                    }
                    if (event.events & EPOLLOUT) {
                        RETURN_IF_ERROR(socket_io->TryWriteOnce());
                    }
                } else {
                    return absl::InternalError("Unknown epoll event");
                }
            }

            // 发送心跳
            if (absl::Now() - last_sent_heartbeat > absl::Seconds(10)) {
                proto::HeartBeat heartbeat;
                proto::Content content;
                *content.mutable_heartbeat() = heartbeat;
                ASSIGN_OR_RETURN(auto send_data,
                                 common::message::Serialize(id, key, content));
                socket_io->AppendWriteData(send_data);
                last_sent_heartbeat = absl::Now();
            }

            while (true) {
                uint64_t consumed_length;
                ASSIGN_OR_RETURN(
                    auto content,
                    common::message::TryParse(id, key, socket_io->DataToRead(),
                                              &consumed_length));
                if (!content.has_value()) {
                    break;
                }
                socket_io->ConsumeReadData(consumed_length);

                if (content->has_new_tcp_forward()) {
                    tm->Launch(std::bind(&Client::TcpForwardThread, this, _1,
                                         _2, content->new_tcp_forward()));
                } else if (content->has_heartbeat()) {
                    last_received_heartbeat = absl::Now();
                } else {
                    return absl::InternalError(absl::StrFormat(
                        "Unsupported message : %s", content->DebugString()));
                }
            }
        }

        return absl::OkStatus();
    }
    void MainThread(uint64_t tid, ThreadManager* tm) {
        try {
            auto status = Main(tid, tm);
            if (!status.ok()) {
                LOG(ERROR) << "main thread error : " << status;
                exit(1);
            } else {
                LOG(INFO) << "main thread exit";
            }
        } catch (...) {
            LOG(ERROR) << "main thread catched an error";
        }
        exit(0);
    }

    absl::Status TcpForwardMain(uint64_t tid, ThreadManager* tm,
                                proto::TcpForward tcp_forward) {
        RETURN_IF_ERROR(tm->SetThreadName(tid, kTcpForwardThreadName));

        std::string id = FLAGS_id;
        std::string key = FLAGS_key;
        absl::Time last_received_heartbeat = absl::Now();
        absl::Time last_sent_heartbeat = absl::Now();

        // ========== tcp forward socket
        ASSIGN_OR_RETURN(auto tcp_forward_socket,
                         net::Socket(AF_INET, SOCK_STREAM, 0));
        ASSIGN_OR_RETURN(auto forward_addr,
                         net::SocketAddr::NewIPv4(tcp_forward.to_ip(),
                                                  tcp_forward.to_port()));
        RETURN_IF_ERROR(tcp_forward_socket->Connect(forward_addr));
        RETURN_IF_ERROR(
            tcp_forward_socket->SetSockOpt<int>(SOL_SOCKET, SO_KEEPALIVE, 1));
        ASSIGN_OR_RETURN(
            auto tcp_forward_io,
            file::NonblockingIO::Create(std::move(tcp_forward_socket)));

        // ========== server socket
        ASSIGN_OR_RETURN(auto socket, net::Socket(AF_INET, SOCK_STREAM, 0));
        ASSIGN_OR_RETURN(auto server_addr,
                         net::SocketAddr::NewIPv4(FLAGS_server, FLAGS_port));
        RETURN_IF_ERROR(socket->Connect(server_addr));
        RETURN_IF_ERROR(socket->SetSockOpt<int>(SOL_SOCKET, SO_KEEPALIVE, 1));
        ASSIGN_OR_RETURN(auto socket_io,
                         file::NonblockingIO::Create(std::move(socket)));

        // send accept tcp forward
        {
            proto::Content content;
            *content.mutable_accept_tcp_forward() = tcp_forward;
            ASSIGN_OR_RETURN(auto send_data,
                             common::message::Serialize(id, key, content));
            socket_io->AppendWriteData(send_data);
        }

        ASSIGN_OR_RETURN(auto epoll, file::EPoll::Create());

        while (true) {
            if (absl::Now() - last_received_heartbeat > absl::Seconds(60)) {
                LOG(INFO) << "Heartbeat timeout";
                break;
            }

            RETURN_IF_ERROR(epoll->DeleteIfExists(socket_io->file()));
            RETURN_IF_ERROR(epoll->DeleteIfExists(tcp_forward_io->file()));
            do {
                if (socket_io->HasDataToWrite()) {
                    RETURN_IF_ERROR(epoll->Add(socket_io->file(), EPOLLOUT));
                    break;
                }
                if (tcp_forward_io->HasDataToWrite()) {
                    RETURN_IF_ERROR(
                        epoll->Add(tcp_forward_io->file(), EPOLLOUT));
                    break;
                }
                RETURN_IF_ERROR(epoll->Add(socket_io->file(), EPOLLIN));
                RETURN_IF_ERROR(epoll->Add(tcp_forward_io->file(), EPOLLIN));
            } while (0);

            absl::Duration timeout = absl::Milliseconds(100);
            ASSIGN_OR_RETURN(auto events, epoll->Wait(1024, &timeout));
            for (const auto& event : events) {
                if (event.file->fd() == socket_io->file()->fd()) {
                    if (event.events & EPOLLIN) {
                        ASSIGN_OR_RETURN(auto read_bytes,
                                         socket_io->TryReadOnce(1024));
                        // 如果可以读数据但是并没有任何数据，那么表示closed
                        if (read_bytes == 0) {
                            return absl::OkStatus();
                        }
                    }
                    if (event.events & EPOLLOUT) {
                        RETURN_IF_ERROR(socket_io->TryWriteOnce());
                    }
                } else if (event.file->fd() == tcp_forward_io->file()->fd()) {
                    if (event.events & EPOLLIN) {
                        ASSIGN_OR_RETURN(auto read_bytes,
                                         tcp_forward_io->TryReadOnce(1024));
                        // 如果可以读数据但是并没有任何数据，那么表示closed
                        if (read_bytes == 0) {
                            return absl::OkStatus();
                        }
                    }
                    if (event.events & EPOLLOUT) {
                        RETURN_IF_ERROR(tcp_forward_io->TryWriteOnce());
                    }
                } else {
                    return absl::InternalError("Unknown epoll event");
                }
            }

            // 发送心跳
            if (absl::Now() - last_sent_heartbeat > absl::Seconds(10)) {
                proto::HeartBeat heartbeat;
                proto::Content content;
                *content.mutable_heartbeat() = heartbeat;
                ASSIGN_OR_RETURN(auto send_data,
                                 common::message::Serialize(id, key, content));
                socket_io->AppendWriteData(send_data);
                last_sent_heartbeat = absl::Now();
            }

            while (true) {
                uint64_t consumed_length;
                ASSIGN_OR_RETURN(
                    auto content,
                    common::message::TryParse(id, key, socket_io->DataToRead(),
                                              &consumed_length));
                if (!content.has_value()) {
                    break;
                }
                socket_io->ConsumeReadData(consumed_length);

                if (content->has_tcp_packet()) {
                    tcp_forward_io->AppendWriteData(
                        content->tcp_packet().data());
                } else if (content->has_heartbeat()) {
                    last_received_heartbeat = absl::Now();
                } else {
                    return absl::InternalError(
                        absl::StrFormat("Unsupported tcp forward message : %s",
                                        content->DebugString()));
                }
            }

            if (tcp_forward_io->HasDataToRead()) {
                proto::TcpPacket packet;
                *packet.mutable_data() =
                    std::string(tcp_forward_io->DataToRead());
                tcp_forward_io->ConsumeReadData(
                    tcp_forward_io->DataToRead().size());
                proto::Content content;
                *content.mutable_tcp_packet() = packet;
                ASSIGN_OR_RETURN(std::string send_data,
                                 common::message::Serialize(id, key, content));
                socket_io->AppendWriteData(send_data);
            }
        }

        return absl::OkStatus();
    }
    void TcpForwardThread(uint64_t tid, ThreadManager* tm,
                          proto::TcpForward tcp_forward) {
        try {
            auto status = TcpForwardMain(tid, tm, tcp_forward);
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
};

}  // namespace

int main(int argc, char* argv[]) {
    FLAGS_logtostderr = true;
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    google::InitGoogleLogging(argv[0]);

    if (FLAGS_server.empty()) {
        LOG(ERROR) << "--server is required";
        return 1;
    }
    if (FLAGS_port == 0) {
        LOG(ERROR) << "--port is required";
        return 1;
    }
    if (FLAGS_id.empty()) {
        LOG(ERROR) << "--id is required";
        return 1;
    }
    if (FLAGS_key.empty()) {
        LOG(ERROR) << "--key is required";
        return 1;
    }

    absl::SleepFor(absl::Seconds(2));
    LOG(INFO) << "Client started";

    Client client;
    ThreadManager tm;

    tm.Launch(std::bind(&Client::MainThread, &client, _1, _2));

    tm.Start();

    return 0;
}
