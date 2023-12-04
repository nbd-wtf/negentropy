package negentropy

const (
	PROTOCOL_VERSION = 0x61
	ID_SIZE          = 32
	FINGERPRINT_SIZE = 16
)

type Mode int

const (
	ModeSkip        Mode = 0
	ModeFingerprint      = 1
	ModeIdList           = 2
)

type Item struct {
	timestamp uint32
	id        [ID_SIZE]byte
}
