# Known Issues

1. **Server Dependency**
   - Client cannot function unless the server is running.
   - A failed server connection causes abrupt termination.

2. **Hardcoded Configuration**
   - Server IP (`127.0.0.1`) and Port (`12345`) are fixed in code.
   - No configuration file or CLI arguments yet.

3. **No Authentication**
   - Any client can connect without credentials.
   - No way to verify user identity.

4. **Basic Error Handling**
   - Exceptions are caught but only display "Connection lost."
   - Errors are not logged or detailed.

5. **Graceful Shutdown**
   - `/quit` command works as intended.
   - However, unexpected socket closures may leave connections hanging.

6. **No Encryption**
   - Messages are exchanged in plain text.
   - Not secure for production environments.

7. **Limited Testing**
   - Only tested on localhost.
   - No multi-platform or large-scale tests yet.
