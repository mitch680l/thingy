# Shell Commands Documentation

This document describes all available shell commands in the embedded system. All commands except `login` require authentication.

## Authentication Commands

### `login <password>`
- **Purpose**: Authenticate with the system
- **Authentication**: Not required (this is the authentication command)
- **Parameters**: 
  - `<password>`: The authentication password
- **Description**: Authenticates the user with the system. After successful authentication, the shell prompt changes from "login>" to "dev>". The system supports lockout after multiple failed attempts and auto-logout after inactivity.
- **Returns**: 
  - `0`: Authentication successful
  - `-EPERM`: Authentication failed
  - `-EAGAIN`: System is locked due to too many failed attempts

### `logout`
- **Purpose**: Logout and re-lock the shell
- **Authentication**: Required
- **Parameters**: None
- **Description**: Logs out the current user and re-locks the shell. The prompt changes back to "login>".
- **Returns**: `0` on success

## Configuration Management Commands (`cfg`)

### `cfg parse`
- **Purpose**: Parse encrypted blob into RAM index
- **Authentication**: Required
- **Parameters**: None
- **Description**: Parses the encrypted configuration blob stored in flash memory and loads it into RAM for access by other commands.
- **Returns**: `0` on success

### `cfg get_config <aad>`
- **Purpose**: Decrypt and display a specific configuration value
- **Authentication**: Required
- **Parameters**:
  - `<aad>`: Additional Authenticated Data (AAD) key to look up
- **Description**: Decrypts and displays the configuration value associated with the specified AAD key.
- **Returns**: 
  - `0`: Value retrieved successfully
  - `-ENOENT`: AAD not found or decryption failed

### `cfg get_all`
- **Purpose**: List all configuration entries
- **Authentication**: Required
- **Parameters**: None
- **Description**: Decrypts and displays all configuration entries in the format "AAD = value".
- **Returns**: `0` on success

### `cfg set <aad> <data>`
- **Purpose**: Create or override a configuration entry
- **Authentication**: Required
- **Parameters**:
  - `<aad>`: Additional Authenticated Data (AAD) key
  - `<data>`: Configuration value to store
- **Description**: Encrypts and stores a new configuration entry. If an entry with the same AAD already exists, it will be overwritten.
- **Returns**: 
  - `0`: Entry created/updated successfully
  - `-ENOSPC`: No free slot available and no matching AAD to override

### `cfg set_page <page:1-2> [aad1 data1] [aad2 data2] ...`
- **Purpose**: Write a full page of configuration entries
- **Authentication**: Required
- **Parameters**:
  - `<page:1-2>`: Page number (1 or 2)
  - `[aad1 data1] [aad2 data2] ...`: Optional pairs of AAD and data values
- **Description**: Creates a complete page image with multiple configuration entries. Each page can hold multiple entries. If AAD/data pairs are provided, they will be encrypted and stored in the page.
- **Returns**: `0` on success

### `cfg get_hex <index>`
- **Purpose**: Display a configuration entry in hexadecimal format
- **Authentication**: Required
- **Parameters**:
  - `<index>`: Entry index (0 to max entries)
- **Description**: Displays the raw hexadecimal data of a configuration entry at the specified index.
- **Returns**: 
  - `0`: Entry displayed successfully
  - `-EINVAL`: Invalid index

### `cfg get_page_hex <page_index:1-2>`
- **Purpose**: Display a page in hexadecimal format
- **Authentication**: Required
- **Parameters**:
  - `<page_index:1-2>`: Page number (1 or 2)
- **Description**: Displays the raw hexadecimal data of an entire configuration page.
- **Returns**: 
  - `0`: Page displayed successfully
  - `-EINVAL`: Invalid page index

### `cfg get_blob_hex`
- **Purpose**: Display the entire encrypted blob in hexadecimal format
- **Authentication**: Required
- **Parameters**: None
- **Description**: Displays the complete encrypted configuration blob in hexadecimal format, including the CRC at the end.
- **Returns**: `0` on success

### `cfg get_crc`
- **Purpose**: Show CRC information
- **Authentication**: Required
- **Parameters**: None
- **Description**: Displays CRC (Cyclic Redundancy Check) information including computed CRC, stored CRC, and validation status.
- **Returns**: `0` on success

### `cfg show_layout`
- **Purpose**: Show memory layout information
- **Authentication**: Required
- **Parameters**: None
- **Description**: Displays detailed information about the encrypted blob memory layout, including addresses, sizes, and page organization.
- **Returns**: `0` on success

### `cfg erase_entry <aad>`
- **Purpose**: Erase a configuration entry by AAD
- **Authentication**: Required
- **Parameters**:
  - `<aad>`: Additional Authenticated Data (AAD) key to erase
- **Description**: Finds and erases the configuration entry with the specified AAD key. The entry is filled with 0xFF to mark it as empty.
- **Returns**: 
  - `0`: Entry erased successfully
  - `-ENOENT`: No entry found with the specified AAD

### `cfg erase page <1|2>`
- **Purpose**: Erase an entire configuration page
- **Authentication**: Required
- **Parameters**:
  - `<1|2>`: Page number to erase
- **Description**: Completely erases a configuration page, filling it with 0xFF.
- **Returns**: 
  - `0`: Page erased successfully
  - `-EINVAL`: Invalid page number

### `cfg crc update`
- **Purpose**: Recompute and write CRC
- **Authentication**: Required
- **Parameters**: None
- **Description**: Recalculates the CRC for the encrypted blob and writes it to the CRC location. This is typically done after modifying the blob contents.
- **Returns**: 
  - `0`: CRC updated successfully
  - Error code: CRC update failed

### `cfg rebuild_blob`
- **Purpose**: Rebuild blob from entries array (compacted layout)
- **Authentication**: Required
- **Parameters**: None
- **Description**: Rebuilds the encrypted blob from the in-memory entries array using a compacted layout, then updates the CRC.
- **Returns**: 
  - `0`: Blob rebuilt successfully
  - Error code: Rebuild failed

### `cfg help`
- **Purpose**: Show help information for cfg commands
- **Authentication**: Required
- **Parameters**: None
- **Description**: Displays comprehensive help information for all cfg subcommands, including usage examples and authentication notes.
- **Returns**: `0` on success

## Key Management Commands (`keymgmt`)

### `keymgmt put <sec_tag> <ca|cert|key> <one_line>`
- **Purpose**: Add a line to a PEM certificate or key
- **Authentication**: Required
- **Parameters**:
  - `<sec_tag>`: Security tag number
  - `<ca|cert|key>`: Type of credential (ca, cert, or key)
  - `<one_line>`: One line of PEM data
- **Description**: Adds a line to a PEM certificate or key being built. The system automatically detects when the PEM data is complete and writes it to the modem's secure storage.
- **Returns**: 
  - `0`: Line added successfully
  - `-EBUSY`: Another session is in progress
  - `-EOVERFLOW`: Data too large for buffer

### `keymgmt status`
- **Purpose**: Show current buffering status
- **Authentication**: Required
- **Parameters**: None
- **Description**: Displays the current status of the key management session, including whether a session is active and the current buffer size.
- **Returns**: `0` on success

### `keymgmt abort`
- **Purpose**: Abort and clear current buffer
- **Authentication**: Required
- **Parameters**: None
- **Description**: Aborts the current key management session and clears the buffer.
- **Returns**: `0` on success

### `keymgmt print`
- **Purpose**: Print current buffer contents with proper line breaks
- **Authentication**: Required
- **Parameters**: None
- **Description**: Displays the current contents of the key management buffer with proper line breaks, showing the PEM data being built.
- **Returns**: `0` on success

## Authentication System Details

### Security Features
- **Password-based authentication**: Uses PBKDF2-SHA256 with configurable iterations
- **Lockout protection**: System locks after multiple failed login attempts
- **Auto-logout**: Automatically logs out users after a period of inactivity
- **Session management**: Tracks authentication state and activity timestamps

### Authentication Flow
1. User must authenticate with `login <password>`
2. After successful authentication, all commands become available
3. Commands automatically extend the session timeout
4. User can manually logout with `logout`
5. System automatically logs out after inactivity period

### Error Handling
- Commands return `-EPERM` when authentication is required but not provided
- Failed authentication attempts are tracked and can trigger lockout
- Lockout periods prevent brute force attacks

## Notes
- All commands except `login` require authentication
- The system uses AES-GCM encryption for configuration data
- Configuration data is stored in flash memory with CRC protection
- Key management commands interface with the modem's secure storage
- Commands are designed to be safe and prevent data corruption
