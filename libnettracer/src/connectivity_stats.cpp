/*
 * Copyright 2026 Dynatrace LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "connectivity_stats.h"
#include "system_utils.h"

namespace netstat {

template <typename IPTYPE>
void print_human_readable(const std::unordered_map<ServerTuple_t<IPTYPE>, ServerStats>& aggr, int field_width, std::ostream& os) {

	for (auto& [tup, stats] : aggr) {

		os << std::setw(field_width) << to_string(tup.get_tuple(), ConnectionDirection::Incoming);
		os << std::setw(field_width) << tup.pid << std::setw(field_width) << stats.bytes_sent << std::setw(field_width)
		   << stats.bytes_received << std::setw(field_width) << stats.rtt << std::setw(field_width) << stats.connection_attempts << "\n";
	}
}

static void printHeader(int field_width, std::ostream& os) {
	os << std::left << std::setw(2 * field_width) << "local address <-> remote address" << std::setw(field_width) << "pid"
	   << std::setw(field_width) << "bytes sent" << std::setw(field_width) << "bytes received " << std::setw(field_width) << "rtt"
	   << std::setw(field_width) << "rtt_var" << std::setw(field_width) << "connectivity" << "\n";
}

void ConnectivityStats::print_human_readable() {
	printHeader(field_width, *os);
	std::unique_lock<std::mutex> l(mx);
	print_human_readable<ipv4_tuple_t>(servers_, field_width, *os);
	print_human_readable<ipv6_tuple_t>(servers6_, field_width, *os);
	print_human_readable_clients();
}

template <typename IPTYPE>
void ConnectivityStats::aggregateServers() {
	auto& aggr{connections<IPTYPE>()};
	for (auto& [tup, stats] : aggr) {
		if (stats.state.Direction != 1) {
			continue;
		}
		auto skey = createServerKey(tup, stats.pid);
		auto& statsExt = servers<IPTYPE>()[skey];
		statsExt.addStats(stats.curr);
	}
}

void ConnectivityStats::aggregateServers() {
	aggregateServers<ipv4_tuple_t>();
	aggregateServers<ipv6_tuple_t>();
}

template <typename IPTYPE, typename EventIPTYPE>
void ConnectivityStats::event(const EventIPTYPE& evt) {
	auto key{eventToTuple(evt)};
	auto time = bpfTimeToSystemTime(evt.timestamp);

	if (key.sport == 0) {
		LOG_DEBUG("Event src port = 0 for {} ", to_string(evt));
		return;
	}

	std::unique_lock<std::mutex> l(mx);
	auto& el = connections<IPTYPE>()[key];

	if (el.state.Closed == 1) {
		LOG_INFO("Event on closed connection {}", to_string(evt));
	}
	el.pid = evt.pid;
	el.update_time = getCurrentTimeFromSteadyClock();
	if (evt.type == TCP_EVENT_TYPE_CONNECT) {
		el.start = time;
		el.state.Established = 1;
		el.state.Direction = 0;

		return;
	}

	key.dport = 0;
	auto skey = createServerKey(key, evt.pid);
	auto& serv = servers<IPTYPE>()[skey];
	serv.update_time = getCurrentTimeFromSteadyClock();

	if (evt.type == TCP_EVENT_TYPE_ACCEPT) {
		el.state.Direction = 1;
		el.state.Established = 1;
		el.start = time;
		serv.session_counter++;

	} else if (evt.type == TCP_EVENT_TYPE_CLOSE) {
		el.state.Closed = 1;
		el.end = time;
		serv.session_counter--;
	} else if (evt.type == TCP_EVENT_TYPE_SYN_ATTEMPT) {
		serv.connection_attempts++;
	} else if (evt.type == TCP_EVENT_TYPE_RST) {
		serv.connection_resets++;
	} else if (evt.type == TCP_EVENT_TYPE_DROP) {
		serv.connection_timeouts++;
	}
}

void ConnectivityStats::eventIpv4(const tcp_ipv4_event_t& evt) {
	return event<ipv4_tuple_t>(evt);
}
void ConnectivityStats::eventIpv6(const tcp_ipv6_event_t& evt) {
	return event<ipv6_tuple_t>(evt);
}
} // namespace netstat
