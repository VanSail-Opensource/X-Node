package protocol

import wire "github.com/VanSail-Opensource/X-Node/internal/protocol"

const ReportFramingCapability = wire.ReportFramingCapability
const ReportFramingHeader = wire.ReportFramingHeader
const ZstdReportFraming = wire.ZstdReportFraming
const ReportZstdLevel = wire.ReportZstdLevel
const MaxReportFrameBytes = wire.MaxReportFrameBytes

type ReportEncoder = wire.ReportEncoder
type ReportDecoder = wire.ReportDecoder

var ErrReportFrame = wire.ErrReportFrame

func NewReportEncoder() (*ReportEncoder, error) { return wire.NewReportEncoder() }
func NewReportDecoder() (*ReportDecoder, error) { return wire.NewReportDecoder() }
func IsReport(kind string) bool                 { return wire.IsReport(kind) }
