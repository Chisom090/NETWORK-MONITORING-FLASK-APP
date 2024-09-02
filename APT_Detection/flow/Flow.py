import statistics
from flow.FlowFeature import FlowFeatures
from datetime import datetime

THRESHOLD = 5  # Use a constant for threshold to avoid magic numbers


class Flow:
    def __init__(self, packet):
        # Initialize packet info lists
        self.packetInfos = [packet]
        self.fwdPacketInfos = [packet]
        self.bwdPacketInfos = []

        # Initialize flow features
        self.flowFeatures = FlowFeatures()
        self._initialize_flow_features(packet)

        # Initialize timing and packet counters
        self.flowLastSeen = self.fwdLastSeen = self.flowStartTime = packet.getTimestamp()
        self.bwdLastSeen = 0
        self.startActiveTime = self.endActiveTime = packet.getTimestamp()
        self.packet_count = 1
        self.fwd_packet_count = 1
        self.bwd_packet_count = 0

        # Initialize IAT and activity tracking lists
        self.flowIAT = []
        self.fwdIAT = []
        self.bwdIAT = []
        self.flowActive = []
        self.flowIdle = []

    def _initialize_flow_features(self, packet):
        """Initializes the flow features based on the first packet."""
        self.flowFeatures.setDestPort(packet.getDestPort())
        self.flowFeatures.setPID(packet.getPID())
        self.flowFeatures.setPName(packet.getPName())
        self.flowFeatures.setFwdPSHFlags(0 if not packet.getURGFlag() else 1)
        self.flowFeatures.setMaxPacketLen(packet.getPayloadBytes())
        self.flowFeatures.setPacketLenMean(packet.getPayloadBytes())
        self.flowFeatures.setFINFlagCount(1 if packet.getFINFlag() else 0)
        self.flowFeatures.setSYNFlagCount(1 if packet.getSYNFlag() else 0)
        self.flowFeatures.setPSHFlagCount(1 if packet.getPSHFlag() else 0)
        self.flowFeatures.setACKFlagCount(1 if packet.getACKFlag() else 0)
        self.flowFeatures.setURGFlagCount(1 if packet.getURGFlag() else 0)
        self.flowFeatures.setAvgPacketSize(packet.getPacketSize())
        self.flowFeatures.setInitBytesFwd(packet.getWinBytes())
        self.flowFeatures.setSrc(packet.getSrc())
        self.flowFeatures.setDest(packet.getDest())
        self.flowFeatures.setSrcPort(packet.getSrcPort())
        self.flowFeatures.setProtocol(packet.getProtocol())

    def getFlowLastSeen(self):
        return self.flowLastSeen

    def getFlowStartTime(self):
        return self.flowStartTime

    def new(self, packetInfo, direction):
        """Updates the flow with a new packet based on the direction (forward/backward)."""
        if direction == 'bwd':
            self._update_backward_packet(packetInfo)
        else:
            self._update_forward_packet(packetInfo)

        self._update_common_features(packetInfo)
        self._update_activity_times(packetInfo.getTimestamp())

    def _update_backward_packet(self, packetInfo):
        """Updates features related to backward packets."""
        self.bwdPacketInfos.append(packetInfo)
        payload_bytes = packetInfo.getPayloadBytes()

        if self.bwd_packet_count == 0:
            # First backward packet initialization
            self.flowFeatures.setBwdPacketLenMax(payload_bytes)
            self.flowFeatures.setBwdPacketLenMin(payload_bytes)
            self.flowFeatures.setInitWinBytesBwd(packetInfo.getWinBytes())
        else:
            self.flowFeatures.setBwdPacketLenMax(
                max(self.flowFeatures.bwd_packet_len_max, payload_bytes))
            self.flowFeatures.setBwdPacketLenMin(
                min(self.flowFeatures.bwd_packet_len_min, payload_bytes))
            self.bwdIAT.append(self._calculate_iat(packetInfo.getTimestamp(), self.bwdLastSeen))

        self.bwd_packet_count += 1
        self.bwdLastSeen = packetInfo.getTimestamp()

    def _update_forward_packet(self, packetInfo):
        """Updates features related to forward packets."""
        self.fwdPacketInfos.append(packetInfo)
        self.fwdIAT.append(self._calculate_iat(packetInfo.getTimestamp(), self.fwdLastSeen))
        self.flowFeatures.setFwdPSHFlags(max(1 if packetInfo.getURGFlag() else 0,
                                             self.flowFeatures.getFwdPSHFlags()))
        self.fwd_packet_count += 1
        self.fwdLastSeen = packetInfo.getTimestamp()

    def _calculate_iat(self, current_timestamp, last_seen_timestamp):
        """Calculates Inter-Arrival Time (IAT) in microseconds."""
        return (current_timestamp - last_seen_timestamp) * 1_000_000

    def _update_common_features(self, packetInfo):
        """Updates features that are common to both forward and backward packets."""
        self.flowFeatures.setMaxPacketLen(max(self.flowFeatures.getMaxPacketLen(), packetInfo.getPayloadBytes()))

        # Update flag counts if present in packet
        flag_methods = {
            packetInfo.getFINFlag: self.flowFeatures.setFINFlagCount,
            packetInfo.getSYNFlag: self.flowFeatures.setSYNFlagCount,
            packetInfo.getPSHFlag: self.flowFeatures.setPSHFlagCount,
            packetInfo.getACKFlag: self.flowFeatures.setACKFlagCount,
            packetInfo.getURGFlag: self.flowFeatures.setURGFlagCount
        }
        for flag_check, flag_setter in flag_methods.items():
            if flag_check():
                flag_setter(1)

        self.packet_count += 1
        self.packetInfos.append(packetInfo)
        self.flowIAT.append(self._calculate_iat(packetInfo.getTimestamp(), self.flowLastSeen))
        self.flowLastSeen = packetInfo.getTimestamp()

    def _update_activity_times(self, current_time):
        """Updates the flow's active and idle times."""
        if current_time - self.endActiveTime > THRESHOLD:
            # If the time difference exceeds the threshold, it's an idle period
            if self.endActiveTime - self.startActiveTime > 0:
                self.flowActive.append(self.endActiveTime - self.startActiveTime)
            self.flowIdle.append(current_time - self.endActiveTime)
            self.startActiveTime = current_time
        self.endActiveTime = current_time

    def terminated(self):
        """Calculates and returns all features when the flow is terminated."""
        duration = self._calculate_iat(self.flowLastSeen, self.flowStartTime)
        self.flowFeatures.setFlowDuration(duration)

        self._calculate_bwd_packet_features()
        self._calculate_flow_iat_features()
        self._calculate_fwd_iat_features()
        self._calculate_bwd_iat_features()
        self._calculate_packet_statistics()

        self._calculate_active_idle_features()

        return self._get_feature_list()

    def _calculate_bwd_packet_features(self):
        """Calculates backward packet length statistics."""
        bwd_packet_lens = [x.getPayloadBytes() for x in self.bwdPacketInfos]
        if bwd_packet_lens:
            self.flowFeatures.setBwdPacketLenMean(statistics.mean(bwd_packet_lens))
            if len(bwd_packet_lens) > 1:
                self.flowFeatures.setBwdPacketLenStd(statistics.stdev(bwd_packet_lens))

    def _calculate_flow_iat_features(self):
        """Calculates flow IAT statistics."""
        if self.flowIAT:
            self.flowFeatures.setFlowIATMean(statistics.mean(self.flowIAT))
            self.flowFeatures.setFlowIATMax(max(self.flowIAT))
            self.flowFeatures.setFlowIATMin(min(self.flowIAT))
            if len(self.flowIAT) > 1:
                self.flowFeatures.setFlowIATStd(statistics.stdev(self.flowIAT))

    def _calculate_fwd_iat_features(self):
        """Calculates forward IAT statistics."""
        if self.fwdIAT:
            self.flowFeatures.setFwdIATTotal(sum(self.fwdIAT))
            self.flowFeatures.setFwdIATMean(statistics.mean(self.fwdIAT))
            self.flowFeatures.setFwdIATMax(max(self.fwdIAT))
            self.flowFeatures.setFwdIATMin(min(self.fwdIAT))
            if len(self.fwdIAT) > 1:
                self.flowFeatures.setFwdIATStd(statistics.stdev(self.fwdIAT))

    def _calculate_bwd_iat_features(self):
        """Calculates backward IAT statistics."""
        if self.bwdIAT:
            self.flowFeatures.setBwdIATTotal(sum(self.bwdIAT))
            self.flowFeatures.setBwdIATMean(statistics.mean(self.bwdIAT))
            self.flowFeatures.setBwdIATMax(max(self.bwdIAT))
            self.flowFeatures.setBwdIATMin(min(self.bwdIAT))
            if len(self.bwdIAT) > 1:
                self.flowFeatures.setBwdIATStd(statistics.stdev(self.bwdIAT))

    def _calculate_packet_statistics(self):
        """Calculates packet statistics such as length mean, std, and variance."""
        packet_lens = [x.getPayloadBytes() for x in self.packetInfos]
        if packet_lens:
            self.flowFeatures.setPacketLenMean(statistics.mean(packet_lens))
            if len(packet_lens) > 1:
                self.flowFeatures.setPacketLenStd(statistics.stdev(packet_lens))
                self.flowFeatures.setPacketLenVariance(statistics.variance(packet_lens))

    def _calculate_active_idle_features(self):
        """Calculates active and idle time statistics."""
        if self.flowActive:
            self.flowFeatures.setActiveMean(statistics.mean(self.flowActive))
            self.flowFeatures.setActiveMax(max(self.flowActive))
            self.flowFeatures.setActiveMin(min(self.flowActive))
            if len(self.flowActive) > 1:
                self.flowFeatures.setActiveStd(statistics.stdev(self.flowActive))

        if self.flowIdle:
            self.flowFeatures.setIdleMean(statistics.mean(self.flowIdle))
            self.flowFeatures.setIdleMax(max(self.flowIdle))
            self.flowFeatures.setIdleMin(min(self.flowIdle))
            if len(self.flowIdle) > 1:
                self.flowFeatures.setIdleStd(statistics.stdev(self.flowIdle))

    def _get_feature_list(self):
        """Returns a list of all flow features."""
        return [
            self.flowFeatures.getDestPort(),
            self.flowFeatures.getPID(),
            self.flowFeatures.getPName(),
            self.packet_count,
            self.flowFeatures.getFwdPSHFlags(),
            self.flowFeatures.getMaxPacketLen(),
            self.flowFeatures.getPacketLenMean(),
            self.flowFeatures.getPacketLenStd(),
            self.flowFeatures.getFlowIATMean(),
            self.flowFeatures.getFlowIATMax(),
            self.flowFeatures.getFlowIATMin(),
            self.flowFeatures.getFlowIATStd(),
            self.flowFeatures.getFwdIATTotal(),
            self.flowFeatures.getFwdIATMean(),
            self.flowFeatures.getFwdIATMax(),
            self.flowFeatures.getFwdIATMin(),
            self.flowFeatures.getFwdIATStd(),
            self.flowFeatures.getBwdIATTotal(),
            self.flowFeatures.getBwdIATMean(),
            self.flowFeatures.getBwdIATMax(),
            self.flowFeatures.getBwdIATMin(),
            self.flowFeatures.getBwdIATStd(),
            self.flowFeatures.getFwdPacketLenMax(),
            self.flowFeatures.getFwdPacketLenMin(),
            self.flowFeatures.getFwdPacketLenMean(),
            self.flowFeatures.getFwdPacketLenStd(),
            self.flowFeatures.getBwdPacketLenMax(),
            self.flowFeatures.getBwdPacketLenMin(),
            self.flowFeatures.getBwdPacketLenMean(),
            self.flowFeatures.getBwdPacketLenStd(),
            self.flowFeatures.getPacketLenVariance(),
            self.flowFeatures.getFlowDuration(),
            self.flowFeatures.getFwdPacketCount(),
            self.flowFeatures.getBwdPacketCount(),
            self.flowFeatures.getSrc(),
            self.flowFeatures.getDest(),
            self.flowFeatures.getSrcPort(),
            self.flowFeatures.getProtocol(),
            self.flowFeatures.getFINFlagCount(),
            self.flowFeatures.getSYNFlagCount(),
            self.flowFeatures.getPSHFlagCount(),
            self.flowFeatures.getACKFlagCount(),
            self.flowFeatures.getURGFlagCount(),
            self.flowFeatures.getInitWinBytesFwd(),
            self.flowFeatures.getInitWinBytesBwd(),
            self.flowFeatures.getActiveMean(),
            self.flowFeatures.getActiveMax(),
            self.flowFeatures.getActiveMin(),
            self.flowFeatures.getActiveStd(),
            self.flowFeatures.getIdleMean(),
            self.flowFeatures.getIdleMax(),
            self.flowFeatures.getIdleMin(),
            self.flowFeatures.getIdleStd()
        ]
