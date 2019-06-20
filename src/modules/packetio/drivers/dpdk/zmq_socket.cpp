#include <cassert>
#include <stdexcept>
#include <string>

#include <zmq.h>

#include "packetio/drivers/dpdk/zmq_socket.h"
#include "core/icp_log.h"

namespace icp::packetio::dpdk {

static int get_socket_fd(void *socket)
{
    int fd = -1;
    size_t fd_size = sizeof(fd);

    if (zmq_getsockopt(socket, ZMQ_FD, &fd, &fd_size) != 0) {
        return (-1);
    }

    return (fd);
}

zmq_socket::zmq_socket(void* socket)
    : m_fd(get_socket_fd(socket))
{
    if (m_fd == -1) {
        throw std::runtime_error("Could not find fd for socket: "
                                 + std::string(zmq_strerror(errno)));
    }
}

uint32_t zmq_socket::poll_id() const
{
    return (m_fd);
}

bool zmq_socket::readable() const
{
    return (m_signal);
}

bool zmq_socket::enable() const { return (true); }

bool zmq_socket::disable() const { return (true); }

int zmq_socket::event_fd() const { return (m_fd); }

static void interrupt_event_callback(int fd __attribute__((unused)), void* arg)
{
    assert(arg);
    auto *signal = reinterpret_cast<int*>(arg);
    *signal = 1;
}

pollable_event<zmq_socket>::event_callback zmq_socket::event_callback_function() const
{
    return (interrupt_event_callback);
}

void* zmq_socket::event_callback_argument()
{
    return (reinterpret_cast<void*>(&m_signal));
}


}
