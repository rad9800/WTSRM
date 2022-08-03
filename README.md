WTSRM - Writing Tiny Small Reliable Malware demo repository for my corresponding [talk.](https://www.youtube.com/watch?v=TfG9lBYCOq8)

- Unhooks all Windows Dlls with \KnownDlls\
- No CRT dependencies
- Small size 
- Low entropy
- Random string encryption key (thus no plaintext strings)
- API hashing
- Hook detection
- Walks around hooks for initial unhooking on ntdll
---
![Diagram](./wtsrm.png)
