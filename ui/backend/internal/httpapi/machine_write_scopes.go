package httpapi

// machineWriteOps is the write operation table (machine-write-scope D1, D13).
// It is empty in T-010: nothing is registered, machineOpFor does not consult
// it, and the v1 allowlist (machineOps) is untouched. Only T-013 registers
// operations here, and each one must also be recorded in
// machineWriteOpenedBy (machine_contract_test.go) with the D-id that opens it.
var machineWriteOps = []machineOp{}

// drillBuildMarker is empty in every default build; the drill-only build tag sets
// it and logs it at start-up (machine_write_drill.go). A default-build test asserts
// it is empty and the artifact check asserts the string is absent from the binary.
var drillBuildMarker = ""
