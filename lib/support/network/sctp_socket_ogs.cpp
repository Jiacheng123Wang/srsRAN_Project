/*
 *
 * Copyright 2021-2024 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include "srsran/support/io/ogs_sctp.h"
#include "srsran/support/io/sctp_socket_ogs.h"
#include "srsran/srslog/srslog.h"
#include "srsran/support/error_handling.h"
#include "srsran/support/io/sockets.h"
#include "srsran/support/srsran_assert.h"
#ifdef __linux__
#include <netinet/sctp.h>
#endif
#ifdef __APPLE__
#include <usrsctp.h>
#endif
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h> /* strtoimax */

using namespace srsran;

// sctp_socket class.
sctp_socket_ogs::sctp_socket_ogs() : logger(srslog::fetch_basic_logger("SCTP-GW")) {}

expected<sctp_socket_ogs> sctp_socket_ogs::create(const sctp_socket_ogs_params& params)
{
  sctp_socket_ogs socket;
  ogs_sock_t *sctp;

  if (params.if_name.empty()) {
    socket.logger.error("Failed to create SCTP socket. Cause: No interface name was provided");
    return make_unexpected(default_error_t{});
  }
  socket.if_name = params.if_name;
  sctp = ogs_sctp_socket(params.ai_family, params.ai_socktype);
  socket.sock_fd = unique_fd{sctp->fd};
  socket.sock_ptr = sctp;

  if (not socket.is_open()) {
    int ret = errno;
    if (ret == ESOCKTNOSUPPORT) {
      // probably the sctp kernel module is missing on the system, inform the user and exit here
      socket.logger.error(
          "{}: Failed to create SCTP socket: {}. Hint: Please ensure 'sctp' kernel module is available on the system.",
          socket.if_name,
          strerror(ret));
      report_error("{}: Failed to create SCTP socket: {}. Hint: Please ensure 'sctp' kernel module is available on the "
                   "system.\n",
                   socket.if_name,
                   strerror(ret));
    }
    return make_unexpected(default_error_t{});
  }
  socket.logger.debug("{}: SCTP socket created with fd={}", socket.if_name, socket.sock_ptr->fd);

  if (not socket.set_sockopts(params)) {
    socket.close();
    return make_unexpected(default_error_t{});
  }

  // Save non-blocking mode to apply after bind/connect. We do not yet support async bind/connect.
  socket.non_blocking_mode = params.non_blocking_mode;

  return socket;
}

sctp_socket_ogs& sctp_socket_ogs::operator=(sctp_socket_ogs&& other) noexcept
{
  sock_fd = std::move(other.sock_fd);
  sock_ptr = other.sock_ptr;
  if_name = std::move(other.if_name);
  return *this;
}

sctp_socket_ogs::~sctp_socket_ogs()
{
  close();
}

bool sctp_socket_ogs::close()
{
  if (not is_open()) {
    return true;
  }
  if (not sock_fd.close()) {
    logger.error("{}: Error closing SCTP socket: {}", if_name, strerror(errno));
    return false;
  } else {
    sock_ptr = nullptr;
  }
  logger.info("{}: SCTP socket closed", if_name);
  if_name.clear();
  return true;
}

bool sctp_socket_ogs::bind(struct sockaddr& ai_addr, const socklen_t& ai_addrlen, const std::string& bind_interface)
{
  if (not is_open()) {
    logger.error("Failed to bind to {}. Cause: Socket is closed", get_nameinfo(ai_addr, ai_addrlen));
    return false;
  }

  if (not bind_to_interface(sock_fd, bind_interface, logger)) {
    return false;
  }

  logger.debug("{}: Binding to {}...", if_name, get_nameinfo(ai_addr, ai_addrlen));

  char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
  if (getnameinfo(&ai_addr, ai_addrlen, hbuf, sizeof(hbuf), sbuf,
            sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) == -1) {
    return false;          
  }
  ogs_sockaddr_t *addr = NULL;
  ogs_getaddrinfo(&addr, ai_addr.sa_family, hbuf, atoi(sbuf), 0);

#ifdef __linux__
  if (ogs_sock_bind(sock_ptr, addr) == -1) {
#endif
#ifdef __APPLE__
  if (ogs_sctp_bind(sock_ptr, addr) == -1) {
#endif
    logger.error("{}: Failed to bind to {}. Cause: {}", if_name, get_nameinfo(ai_addr, ai_addrlen), strerror(errno));
    return false;
  }

  logger.info("{}: Bind to {} was successful", if_name, get_nameinfo(ai_addr, ai_addrlen));

  // set socket to non-blocking after bind is successful
  if (non_blocking_mode) {
    if (not set_non_blocking()) {
      return false;
    }
  }

  return true;
}

bool sctp_socket_ogs::connect(struct sockaddr& ai_addr, const socklen_t& ai_addrlen)
{
  logger.debug("{}: Connecting to {}...", if_name, get_nameinfo(ai_addr, ai_addrlen));
  if (not is_open()) {
    logger.error("Failed to connect to {}. Cause: socket is closed", get_nameinfo(ai_addr, ai_addrlen));
    return false;
  }

  std::array<char, NI_MAXHOST> ip_addr;
  int                          port;
  if (not getnameinfo(ai_addr, ai_addrlen, ip_addr, port)) {
    return false;
  }
  ogs_sockaddr_t *addr;
  ogs_getaddrinfo(&addr, ai_addr.sa_family, ip_addr.data(), port, 0);

  if (ogs_sctp_connect(sock_ptr, addr) == -1) {
    logger.debug("{}: Failed to connect to {} - {}", if_name, get_nameinfo(ai_addr, ai_addrlen), strerror(errno));
    return false;
  }

  // set socket to non-blocking after connect is established
  if (non_blocking_mode) {
    if (not set_non_blocking()) {
      return false;
    }
  }

  return true;
}

bool sctp_socket_ogs::listen()
{
  if (not is_open()) {
    logger.error("{}: Failed to listen for new SCTP connections. Cause: socket is closed", if_name);
    return false;
  }
  // Listen for connections
#ifdef __linux__
  int ret = ogs_sock_listen(sock_ptr);
#endif
#ifdef __APPLE__
  int ret = ogs_sctp_listen(sock_ptr);
#endif
  if (ret != 0) {
    logger.error("{}: Error in SCTP socket listen: {}", if_name, strerror(errno));
    return false;
  }
  if (logger.info.enabled()) {
    // Note: avoid computing the listen_port if log channel is disabled.
    uint16_t port = get_listen_port().value();
    logger.info("{}: Listening for new SCTP connections on port {}...", if_name, port);
  }
  return true;
}

bool sctp_socket_ogs::set_non_blocking()
{
  return ::set_non_blocking(sock_fd, logger);
}

bool sctp_socket_ogs::set_sockopts(const sctp_socket_ogs_params& params)
{
  logger.debug("Setting socket options. params=[{}]", params);

  if (params.rx_timeout.count() > 0) {
    if (not set_receive_timeout(sock_fd, params.rx_timeout, logger)) {
      return false;
    }
  }

  ogs_sockopt_t option;
  ogs_sockopt_init(&option);

  // Set SRTO value
  if (params.rto_initial.has_value()) {
    option.sctp.srto_initial = params.rto_initial.value();
  }
  if (params.rto_min.has_value()) {
    option.sctp.srto_min = params.rto_min.value();
  }
  if (params.rto_max.has_value()) {
    option.sctp.srto_max = params.rto_max.value();
  }
  if (ogs_sctp_rto_info(sock_ptr, &option) == -1) {
    logger.error("{}: Error setting RTO_INFO sockopts. errno={}", if_name, strerror(errno));
    return false;
  }

  // Set SCTP init options
  if (params.init_max_attempts.has_value()) {
    option.sctp.sinit_max_attempts = params.init_max_attempts.value();
  }
  if (params.max_init_timeo.has_value()) {
    option.sctp.sinit_max_init_timeo = params.max_init_timeo.value();
  }
  if (ogs_sctp_initmsg(sock_ptr, &option) == -1) {
    logger.error("{}: Error setting SCTP_INITMSG sockopts. errno={}\n", if_name, strerror(errno));
    return false;
  }

  // Set SCTP NODELAY option
  if (params.nodelay.has_value()) {
    int optval = params.nodelay.value() ? 1 : 0;
    if (ogs_sctp_nodelay(sock_ptr, optval) == -1) {
      logger.error(
        "{}: Could not set SCTP_NODELAY. optval={} error={}", if_name, params.nodelay.value() ? 1 : 0, strerror(errno));
      return false;
    }
  }

  if (params.reuse_addr) {
    int on = 1;
    if (ogs_listen_reusable(sock_ptr->fd, on) == -1) {
      return false;
    }
  }

  return true;
}

std::optional<uint16_t> sctp_socket_ogs::get_listen_port() const
{
  if (not is_open()) {
    logger.error("Socket of SCTP network gateway not created.");
    return {};
  }

  sockaddr_storage gw_addr_storage;
  sockaddr*        gw_addr     = (sockaddr*)&gw_addr_storage;
  socklen_t        gw_addr_len = sizeof(gw_addr_storage);

  int ret = getsockname(sock_ptr->fd, gw_addr, &gw_addr_len);
  if (ret != 0) {
    logger.error("{}: Failed `getsockname` in SCTP network gateway with sock_fd={}: {}",
                 if_name,
                 sock_ptr->fd,
                 strerror(errno));
    return {};
  }

  uint16_t gw_listen_port;
  if (gw_addr->sa_family == AF_INET) {
    gw_listen_port = ntohs(((sockaddr_in*)gw_addr)->sin_port);
  } else if (gw_addr->sa_family == AF_INET6) {
    gw_listen_port = ntohs(((sockaddr_in6*)gw_addr)->sin6_port);
  } else {
    logger.error("{}: Unhandled address family in SCTP network gateway with sock_fd={} family={}",
                 if_name,
                 sock_ptr->fd,
                 gw_addr->sa_family);
    return {};
  }

  return gw_listen_port;
}
