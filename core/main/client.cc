#include <set>
#include <string>
#include <vector>

#include "absl/strings/str_format.h"
#include "absl/time/time.h"
#include "file/epoll.h"
#include "file/filesystem.h"
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

        ASSIGN_OR_RETURN(auto socket, net::Socket(AF_INET, SOCK_STREAM, 0));
        ASSIGN_OR_RETURN(auto server_addr,
                         net::SocketAddr::NewIPv4(FLAGS_server, FLAGS_port));
        RETURN_IF_ERROR(socket->Connect(server_addr));

        {  // ping
            proto::Ping ping;
            ping.set_message("hello world");
            proto::Content content;
            *content.mutable_ping() = ping;
            ASSIGN_OR_RETURN(std::string data,
                             common::message::Serialize(id, key, content));
            RETURN_IF_ERROR(socket->WriteAll(data));
        }

        ASSIGN_OR_RETURN(auto epoll, file::EPoll::Create());
        RETURN_IF_ERROR(epoll->Add(socket.get(), EPOLLIN));

        std::string socket_data;
        while (true) {
            absl::Duration timeout = absl::Milliseconds(100);
            ASSIGN_OR_RETURN(auto events, epoll->Wait(1024, &timeout));
            if (events.empty()) {
                continue;
            }

            ASSIGN_OR_RETURN(std::string data, socket->Read(1024));
            if (data.empty()) {
                return absl::InternalError("Socket closed");
            }
            absl::StrAppend(&socket_data, data);

            uint64_t consumed_length;
            ASSIGN_OR_RETURN(auto content,
                             common::message::TryParse(id, key, socket_data,
                                                       &consumed_length));
            if (!content.has_value()) {
                continue;
            }
            socket_data = socket_data.substr(consumed_length);

            if (content->has_new_tcp_forward()) {
                tm->Launch(std::bind(&Client::TcpForwardThread, this, _1, _2,
                                     content->new_tcp_forward()));
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

        // ========== tcp forward socket
        ASSIGN_OR_RETURN(auto tcp_forward_socket,
                         net::Socket(AF_INET, SOCK_STREAM, 0));
        ASSIGN_OR_RETURN(auto forward_addr,
                         net::SocketAddr::NewIPv4(tcp_forward.to_ip(),
                                                  tcp_forward.to_port()));
        RETURN_IF_ERROR(tcp_forward_socket->Connect(forward_addr));

        // ========== server socket
        ASSIGN_OR_RETURN(auto socket, net::Socket(AF_INET, SOCK_STREAM, 0));
        ASSIGN_OR_RETURN(auto server_addr,
                         net::SocketAddr::NewIPv4(FLAGS_server, FLAGS_port));
        RETURN_IF_ERROR(socket->Connect(server_addr));

        // send accept tcp forward
        {
            proto::Content content;
            *content.mutable_accept_tcp_forward() = tcp_forward;
            ASSIGN_OR_RETURN(auto send_data,
                             common::message::Serialize(id, key, content));
            RETURN_IF_ERROR(socket->WriteAll(send_data));
        }

        std::string tcp_forward_socket_data;
        std::string socket_data;

        ASSIGN_OR_RETURN(auto epoll, file::EPoll::Create());
        RETURN_IF_ERROR(epoll->Add(socket.get(), EPOLLIN));
        RETURN_IF_ERROR(epoll->Add(tcp_forward_socket.get(), EPOLLIN));

        while (true) {
            absl::Duration timeout = absl::Milliseconds(100);
            ASSIGN_OR_RETURN(auto events, epoll->Wait(1024, &timeout));
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

            while (true) {
                uint64_t consumed_length;
                ASSIGN_OR_RETURN(auto content,
                                 common::message::TryParse(id, key, socket_data,
                                                           &consumed_length));
                if (!content.has_value()) {
                    break;
                }
                socket_data = socket_data.substr(consumed_length);

                if (!content->has_tcp_packet()) {
                    RETURN_IF_ERROR(socket->WriteAll("Only need tcp packet"));
                    return absl::InternalError(absl::StrFormat(
                        "Only need tcp packet : %s", content->DebugString()));
                }

                RETURN_IF_ERROR(
                    tcp_forward_socket->WriteAll(content->tcp_packet().data()));
            }

            if (!tcp_forward_socket_data.empty()) {
                proto::TcpPacket packet;
                *packet.mutable_data() = tcp_forward_socket_data;
                tcp_forward_socket_data.clear();
                proto::Content content;
                *content.mutable_tcp_packet() = packet;
                ASSIGN_OR_RETURN(std::string send_data,
                                 common::message::Serialize(id, key, content));
                RETURN_IF_ERROR(socket->WriteAll(send_data));
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

    LOG(INFO) << "Client started";

    Client client;
    ThreadManager tm;

    tm.Launch(std::bind(&Client::MainThread, &client, _1, _2));

    tm.Start();

    return 0;
}
