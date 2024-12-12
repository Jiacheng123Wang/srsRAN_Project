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

#include "srsran/support/io/sctp_socket_usr.h"
#include "srsran/srslog/srslog.h"
#include "srsran/support/error_handling.h"
#include "srsran/support/srsran_assert.h"
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <usrsctp.h>
#include <arpa/inet.h>
#include <inttypes.h> /* strtoimax */

using namespace srsran;

namespace {

/// Subscribes to various SCTP events to handle association and shutdown gracefully.
static bool usrsctp_subscribe_to_events(struct socket* so)
{
  srsran_sanity_check(so != nullptr, "Invalid socket pointer");

  struct usrsctp_event event;
  uint16_t event_types[] = {USR_SCTP_ASSOC_CHANGE,
	                          USR_SCTP_PEER_ADDR_CHANGE,
	                          USR_SCTP_REMOTE_ERROR,
	                          USR_SCTP_SHUTDOWN_EVENT,
	                          USR_SCTP_ADAPTATION_INDICATION,
	                          USR_SCTP_PARTIAL_DELIVERY_EVENT};
  memset(&event, 0, sizeof(event));
  event.se_assoc_id = USR_SCTP_FUTURE_ASSOC;
  event.se_on = 1;
  for (unsigned int i = 0, event_num = sizeof(event_types)/sizeof(uint16_t); i != event_num; i++) {
    event.se_type = event_types[i];
    if (usrsctp_setsockopt(so, IPPROTO_SCTP, USR_SCTP_EVENT, &event, sizeof(struct usrsctp_event)) < 0) {
      return false;
	}
  }
  return true;
}

/// \brief Modify SCTP default parameters for quicker detection of broken links.
/// Changes to the maximum re-transmission timeout (rto_max).
static bool usrsctp_set_rto_opts(struct socket* so,
                       std::optional<int>    rto_initial,
                       std::optional<int>    rto_min,
                       std::optional<int>    rto_max,
                       const std::string&    if_name,
                       srslog::basic_logger& logger)
{
  srsran_sanity_check(so != nullptr, "Invalid USR SCTP socket");

  if (not rto_initial.has_value() && not rto_min.has_value() && not rto_max.has_value()) {
    // no need to set RTO
    return true;
  }

  // Set RTO_MAX to quickly detect broken links
  struct usrsctp_rtoinfo rtoinfo  = {};
  socklen_t    rtoinfo_size       = sizeof(struct usrsctp_rtoinfo);
  rtoinfo.srto_assoc_id = 0;
  if (usrsctp_getsockopt(so, IPPROTO_SCTP, USR_SCTP_RTOINFO, &rtoinfo, &rtoinfo_size) < 0) {
    logger.error("{}: Error getting RTO_INFO sockopts - {}", if_name, strerror(errno));
    // Responsibility of closing the socket is on the caller
    return false;
  }

  if (rto_initial.has_value()) {
    rtoinfo.srto_initial = rto_initial.value();
  }
  if (rto_min.has_value()) {
    rtoinfo.srto_min = rto_min.value();
  }
  if (rto_max.has_value()) {
    rtoinfo.srto_max = rto_max.value();
  }
  logger.debug(
      "{}: Setting RTO_INFO options on SCTP socket. Association {}, Initial RTO {}, Minimum RTO {}, Maximum RTO {}",
      if_name,
      rtoinfo.srto_assoc_id,
      rtoinfo.srto_initial,
      rtoinfo.srto_min,
      rtoinfo.srto_max);

	if (usrsctp_setsockopt(so, IPPROTO_SCTP, USR_SCTP_RTOINFO, (const void *)&rtoinfo, (socklen_t)sizeof(struct usrsctp_rtoinfo)) < 0) {
    logger.error("{}: Error setting RTO_INFO sockopts - {}", if_name, strerror(errno));
		return false;
	}

  return true;
}

/// \brief Modify SCTP default parameters for quicker detection of broken links.
/// Changes to the SCTP_INITMSG parameters (to control the timeout of the connect() syscall)
static bool usrsctp_set_init_msg_opts(struct socket*     so,
                            std::optional<int>    init_max_attempts,
                            std::optional<int>    max_init_timeo,
                            const std::string&    if_name,
                            srslog::basic_logger& logger)
{
  srsran_sanity_check(so != nullptr, "Invalid USR SCTP socket");

  if (not init_max_attempts.has_value() && not max_init_timeo.has_value()) {
    // No value set for init max attempts or max init_timeo,
    // no need to call set_sockopts()
    return true;
  }

  // Set SCTP INITMSG options to reduce blocking timeout of connect()
  struct usrsctp_initmsg init_opts = {};
  socklen_t    init_sz   = sizeof(usrsctp_initmsg);
  if (usrsctp_getsockopt(so, IPPROTO_SCTP, USR_SCTP_INITMSG, &init_opts, &init_sz) < 0) {
    logger.error("{}: Error getting sockopts. errno={}", if_name, strerror(errno));
    return false; // Responsibility of closing the socket is on the caller
  }

  if (init_max_attempts.has_value()) {
    init_opts.sinit_max_attempts = init_max_attempts.value();
  }
  if (max_init_timeo.has_value()) {
    init_opts.sinit_max_init_timeo = max_init_timeo.value();
  }

  logger.debug("{}: Setting SCTP_INITMSG options on USRSCTP socket. Max attempts {}, Max init attempts timeout {}",
               if_name,
               init_opts.sinit_max_attempts,
               init_opts.sinit_max_init_timeo);
  if (usrsctp_setsockopt(so, IPPROTO_SCTP, USR_SCTP_INITMSG, &init_opts, init_sz) < 0) {
    logger.error("{}: Error setting SCTP_INITMSG sockopts. errno={}\n", if_name, strerror(errno));
    return false; // Responsibility of closing the socket is on the caller
  }
  return true;
}

/// Set or unset SCTP_NODELAY. With NODELAY enabled, SCTP messages are sent as soon as possible with no unnecessary
/// delay, at the cost of transmitting more packets over the network. Otherwise their transmission might be delayed and
/// concatenated with subsequent messages in order to transmit them in one big PDU.
///
/// Note: If the local interface supports jumbo frames (MTU size > 1500) but not the receiver, then the receiver might
/// discard big PDUs and the stream might get stuck.
static bool usrsctp_set_nodelay(struct socket* so, std::optional<bool> nodelay)
{
  if (not nodelay.has_value()) {
    // no need to change anything
    return true;
  }

  int optval = nodelay.value() ? 1 : 0;
  return usrsctp_setsockopt(so, IPPROTO_SCTP, USR_SCTP_NODELAY, &optval, sizeof(optval)) == 0;
}

static bool bind_to_interface(const struct socket* so, const std::string& interface, srslog::basic_logger& logger)
{
  if (interface.empty() || interface == "auto") {
    // no need to change anything
    return true;
  }
// to be implemented fo normal interface name

  return true;
}

// static bool str_to_uint16(const char *str, uint16_t *res)
// {
//   char *end;
//   errno = 0;
//   intmax_t val = strtoimax(str, &end, 10);
//   if (errno == ERANGE || val < 0 || val > UINT16_MAX || end == str || *end != '\0')
//     return false;
//   *res = (uint16_t) val;
//   return true;
// }
} // namespace

// sctp_socket_usr class.

sctp_socket_usr::sctp_socket_usr() : logger(srslog::fetch_basic_logger("SCTP-GW")) {
}

// expected<sctp_socket_usr> sctp_socket_usr::create(const usrsctp_socket_params& params) {
//   sctp_socket_usr socket;

//   usrsctp_init(params.bind_port, NULL, NULL);

//   if (params.if_name.empty()) {
//     socket.logger.error("Failed to create SCTP socket. Cause: No interface name was provided");
//     return make_unexpected(default_error_t{});
//   }
//   socket.if_name = params.if_name;
//   socket.sock_ptr = usrsctp_socket(params.ai_family, params.ai_socktype, IPPROTO_SCTP, NULL, NULL, 0, NULL);
//   if (not socket.is_open()) {
//     int ret = errno;
//     if (ret == ESOCKTNOSUPPORT) {
//       // probably the sctp kernel module is missing on the system, inform the user and exit here
//       socket.logger.error(
//           "{}: Failed to create SCTP socket: {}. Hint: Please ensure 'sctp' kernel module is available on the system.",
//           socket.if_name,
//           strerror(ret));
//       report_error("{}: Failed to create SCTP socket: {}. Hint: Please ensure 'sctp' kernel module is available on the "
//                    "system.\n",
//                    socket.if_name,
//                    strerror(ret));
//     }
//     return make_unexpected(default_error_t{});
//   }
//   socket.logger.debug("{}: SCTP socket created...", socket.if_name);

// //   if (not socket.set_sockopts(params)) {
// //     socket.close();
// //     return make_unexpected(default_error_t{});
// //   }

//   // Save non-blocking mode to apply after bind/connect. We do not yet support async bind/connect.
//   socket.non_blocking_mode = params.non_blocking_mode;

//   return socket;
// }
expected<sctp_socket_usr> sctp_socket_usr::create(const usrsctp_socket_params& params) {
  sctp_socket_usr socket;

  usrsctp_init(params.bind_port, NULL, NULL);

  if (params.if_name.empty()) {
    socket.logger.error("Failed to create SCTP socket. Cause: No interface name was provided");
    return make_unexpected(default_error_t{});
  }
  socket.if_name = params.if_name;
  socket.sock_ptr = usrsctp_socket(params.ai_family, params.ai_socktype, IPPROTO_SCTP, NULL, NULL, 0, NULL);
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
  socket.logger.debug("{}: SCTP socket created...", socket.if_name);

//   if (not socket.set_sockopts(params)) {
//     socket.close();
//     return make_unexpected(default_error_t{});
//   }

  // Save non-blocking mode to apply after bind/connect. We do not yet support async bind/connect.
  socket.non_blocking_mode = params.non_blocking_mode;

  return socket;
}

sctp_socket_usr& sctp_socket_usr::operator=(sctp_socket_usr&& other) noexcept
{
  sock_ptr = std::move(other.sock_ptr);
  if_name = std::move(other.if_name);
  return *this;
}

sctp_socket_usr::~sctp_socket_usr()
{
  // close();
}

bool sctp_socket_usr::close()
{
  if (sock_ptr == nullptr) {
    return true;
  }

  if (usrsctp_shutdown(sock_ptr, SHUT_WR) < 0) {
    logger.error("failed to shutdown USRSCTP socket");
  }
  while (usrsctp_finish() != 0) {
    sleep(1);
  }
  logger.info("{}: USRSCTP socket closed", if_name);
  if_name.clear();
  return true;
}

bool sctp_socket_usr::bind(struct sockaddr& ai_addr, const socklen_t& ai_addrlen, const std::string& bind_interface)
{
  char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
  if (getnameinfo(&ai_addr, ai_addrlen, hbuf, sizeof(hbuf), sbuf,
              sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) < 0) {
       logger.error("{}: Failed to bind, can not get name info for address - {}", if_name, strerror(errno));
  }

  if (not is_open()) {
    logger.error("{}: Failed to bind to {}:{}. Cause: Socket is closed", if_name, hbuf, sbuf);
    return false;
  }

  if (not bind_to_interface(sock_ptr, bind_interface, logger)) {
    return false;
  }

  logger.debug("{}: Binding to {}:{}...", if_name, hbuf, sbuf);

  if (usrsctp_bind(sock_ptr, &ai_addr, ai_addrlen) < 0) {
    logger.error("{}: Failed to bind to {}:{}. Cause: {}", if_name, if_name, hbuf, strerror(errno));
    return false;
  }

  logger.info("{}: Bind to {}:{} was successful", if_name, if_name, hbuf);

  // set socket to non-blocking after bind is successful
  if (non_blocking_mode) {
    if (not set_non_blocking()) {
      return false;
    }
  }

  return true;
}

bool sctp_socket_usr::connect(struct sockaddr& ai_addr, const socklen_t& ai_addrlen)
{
  struct sockaddr_in servaddr;
  const char *name;
  uint16_t port;
  if (ai_addr.sa_family == AF_INET) {
    servaddr.sin_family = AF_INET;
  
    struct sockaddr_in *sin = (struct sockaddr_in *)&ai_addr;
    char buf[INET_ADDRSTRLEN];
	  name = inet_ntop(AF_INET, &sin->sin_addr, buf, INET_ADDRSTRLEN);
    servaddr.sin_addr.s_addr = inet_addr(name);
    port = htons(sin->sin_port);
    servaddr.sin_port = port;
  } else if (ai_addr.sa_family == AF_INET6) {
    servaddr.sin_family = AF_INET6;

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ai_addr;
    char buf[INET6_ADDRSTRLEN];
    name = inet_ntop(AF_INET6, &sin6->sin6_addr, buf, INET6_ADDRSTRLEN);
    servaddr.sin_addr.s_addr = inet_addr(name);
    port = htons(sin6->sin6_port);
    servaddr.sin_port = port;
  } else {
    logger.error("{}: Failed to connect to address. Cause: Unsupported address family {}", if_name, ai_addr.sa_family);
    return false;    
  }

  if (usrsctp_connect(sock_ptr, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in)) < 0 ) {
    logger.debug("{}: Failed to connect to {}:{} - {}", if_name, name, port, strerror(errno));
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

bool sctp_socket_usr::listen()
{
  if (not is_open()) {
    logger.error("{}: Failed to listen for new SCTP connections. Cause: socket is closed", if_name);
    return false;
  }
  // Listen for connections
  if (usrsctp_listen(sock_ptr, 1) < 0) {
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

bool sctp_socket_usr::set_non_blocking()
{
  return (not (usrsctp_set_non_blocking(sock_ptr, 1) < 0));
}

bool sctp_socket_usr::set_sockopts(const usrsctp_socket_params& params)
{
  logger.debug("Setting socket options. params=[{}]", params);
  if (not usrsctp_subscribe_to_events(sock_ptr)) {
    logger.error( "{}: SCTP failed to be created - {}", if_name, strerror(errno));
    return false;
  }

  if (params.rx_timeout.count() > 0) { // to be updated
    // sock_ptr->so_rcv.sb_timeo = params.rx_timeout.count();
  }

  // Set SRTO_MAX
  if (not usrsctp_set_rto_opts(sock_ptr, params.rto_initial, params.rto_min, params.rto_max, if_name, logger)) {
    return false;
  }

  // Set SCTP init options
  if (not usrsctp_set_init_msg_opts(sock_ptr, params.init_max_attempts, params.max_init_timeo, if_name, logger)) {
    return false;
  }

  // Set SCTP NODELAY option
  if (not usrsctp_set_nodelay(sock_ptr, params.nodelay)) {
    logger.error(
        "{}: Could not set SCTP_NODELAY. optval={} error={}", if_name, params.nodelay.value() ? 1 : 0, strerror(errno));
    return false;
  }

  if (params.reuse_addr) {
    int optval = 1;
    if (usrsctp_setsockopt(sock_ptr, IPPROTO_SCTP, USR_SCTP_REUSE_PORT, &optval, sizeof(optval)) < 0) {
      return false;
    }
  }

  return true;
}

std::optional<uint16_t> sctp_socket_usr::get_listen_port() const
{
  if (not is_open()) {
    logger.error("Socket of SCTP network gateway not created.");
    return {};
  }

  struct sockaddr *addrs;
	if (usrsctp_getladdrs(sock_ptr, 0, &addrs) < 0) {
    logger.error("{}: Failed `getsockname` in SCTP network gateway - {}", if_name, strerror(errno));
    return {};
	}

  uint16_t listen_port;
  if (addrs->sa_family == AF_INET) {
    listen_port = ntohs(((sockaddr_in*)addrs)->sin_port);
  } else if (addrs->sa_family == AF_INET6) {
    listen_port = ntohs(((sockaddr_in6*)addrs)->sin6_port);
  } else {
    logger.error("{}: Unhandled address family in SCTP network gateway with family={}", if_name, addrs->sa_family);
    return {};
  }

  return listen_port;
}
