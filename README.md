# Vuln-Strix
A standalone vulnerability trend tracker for Nessus. Turns point-in-time scans into historical intelligence.

## Getting Started

### Prerequisites
- Go 1.22+
- GCC (for SQLite CGO) if on Windows (e.g., TDM-GCC or MinGW)

### Building
```powershell
go build -o vuln-strix.exe ./cmd/vuln-strix
```

### Running with Sample Data
1. **Generate Sample Data**
   Creates mock `.nessus` files in `samples/` directory.
   ```powershell
   go run cmd/sample-data/main.go
   ```

2. **Ingest Baseline Scan**
   Ingest the first scan (Host A has 2 vulnerabilities).
   ```powershell
   ./vuln-strix.exe ingest -file samples/scan1_baseline.nessus
   ```

3. **Start Server**
   ```powershell
   ./vuln-strix.exe server
   ```
   Visit [http://localhost:8080](http://localhost:8080) to see the dashboard. Host A will show 2 active vulnerabilities.

4. **Ingest Remediation Scan**
   Stop the server (Ctrl+C), then ingest the second scan (Host A has fixed 1 vuln).
   ```powershell
   ./vuln-strix.exe ingest -file samples/scan2_remediation.nessus
   ```
   *Note: In production, the server can run continuously while you ingest from another terminal.*

5. **Verify Resolution**
   Start the server again and check Host A details. You should see "Active" and "Resolved" tabs.

## Commands
- `ingest -file <path>`: Parse and ingest a Nessus XML file.
- `server -port <port>`: Start the web dashboard.
- `install`: Install as a system service.
- `start/stop`: Control the system service.
