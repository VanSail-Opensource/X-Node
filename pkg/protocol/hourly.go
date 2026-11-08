package protocol

import wire "github.com/VanSail-Opensource/X-Node/internal/protocol"

const (
	HourlyCapability           = wire.HourlyCapability
	HourlyHeader               = wire.HourlyHeader
	HourlyFormat               = wire.HourlyFormat
	HourlySessionHeader        = wire.HourlySessionHeader
	HourlyAccountingHeader     = wire.HourlyAccountingHeader
	HourlyAccountingFormat     = wire.HourlyAccountingFormat
	HourlyCreditInstallCommand = wire.HourlyCreditInstallCommand
	HourlyCreditSealCommand    = wire.HourlyCreditSealCommand
	HourlyCreditAckCommand     = wire.HourlyCreditAckCommand
	MaxHourlyItems             = wire.MaxHourlyItems
	MaxHourlyFrameBytes        = wire.MaxHourlyFrameBytes
	MaxHourlyBurstBytes        = wire.MaxHourlyBurstBytes
	MaxHourlyLifetimeMillis    = wire.MaxHourlyLifetimeMillis
)

type HourlyOwner = wire.HourlyOwner
type HourlyUser = wire.HourlyUser
type HourlyDemand = wire.HourlyDemand
type HourlyDemandBatch = wire.HourlyDemandBatch
type HourlyGrant = wire.HourlyGrant
type HourlyGrantAck = wire.HourlyGrantAck
type HourlyGrantAckBatch = wire.HourlyGrantAckBatch
type HourlySample = wire.HourlySample
type HourlyCreditInstall = wire.HourlyCreditInstall
type HourlyCreditProgress = wire.HourlyCreditProgress
type HourlyCreditProof = wire.HourlyCreditProof
type HourlyCreditProofBatch = wire.HourlyCreditProofBatch
type HourlyCreditSeal = wire.HourlyCreditSeal
type HourlyCreditAck = wire.HourlyCreditAck

func HourlyInstallDigest(value HourlyCreditInstall) string { return wire.HourlyInstallDigest(value) }
func HourlyProofDigest(value HourlyCreditProof) string     { return wire.HourlyProofDigest(value) }
func ValidateHourlyOwner(value HourlyOwner) error          { return wire.ValidateHourlyOwner(value) }
func ValidHourlyDay(value string) bool                     { return wire.ValidHourlyDay(value) }
func ValidateHourlyDemand(value HourlyDemand) error        { return wire.ValidateHourlyDemand(value) }
func ValidateHourlyDemandBatch(value HourlyDemandBatch) error {
	return wire.ValidateHourlyDemandBatch(value)
}
func ValidateHourlyGrant(value HourlyGrant) error       { return wire.ValidateHourlyGrant(value) }
func ValidateHourlyGrantAck(value HourlyGrantAck) error { return wire.ValidateHourlyGrantAck(value) }
func ValidateHourlyGrantAckBatch(value HourlyGrantAckBatch) error {
	return wire.ValidateHourlyGrantAckBatch(value)
}
func ValidateHourlySample(value HourlySample) error         { return wire.ValidateHourlySample(value) }
func ValidateHourlyInstall(value HourlyCreditInstall) error { return wire.ValidateHourlyInstall(value) }
func ValidateHourlyProgress(value HourlyCreditProgress) error {
	return wire.ValidateHourlyProgress(value)
}
func ValidateHourlyProof(value HourlyCreditProof) error { return wire.ValidateHourlyProof(value) }
func ValidateHourlyAck(value HourlyCreditAck) error     { return wire.ValidateHourlyAck(value) }
func ValidateHourlySeal(value HourlyCreditSeal) error   { return wire.ValidateHourlySeal(value) }
func ValidateHourlyProofBatch(value HourlyCreditProofBatch) error {
	return wire.ValidateHourlyProofBatch(value)
}
