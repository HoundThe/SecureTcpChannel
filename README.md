# SecureTCPChannel

## TPM Instructions
The project uses only a TPM Simulator to guarantee functionality even on machines 
that do not have a TPM Chip. The TPM Simulator of choice is the IBM Simulator: https://sourceforge.net/projects/ibmswtpm2/

Once the simulator is compiled, move the binary `tpm_server` into the project and run it. You should see
that the simulator is listening on ports 2321 and 2322.

As for the libraries, this project uses `tpm2-pytss`: https://github.com/tpm2-software/tpm2-pytss

Note that for the library to run, you need to also install `tpm2-tss`: https://github.com/tpm2-software/tpm2-tss
