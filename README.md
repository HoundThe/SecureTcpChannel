# SecureTCPChannel

## TPM Instructions
The project uses only a TPM Simulator to guarantee functionality even on machines 
that do not have a TPM Chip. The TPM Simulator of choice is the IBM Simulator: https://sourceforge.net/projects/ibmswtpm2/

The installation instructions for the TPM Simulator should be found in a `.doc` file, e.g: `ibmtpm.doc` . On Linux, the
only step needed should be to run `make` in the `src` directory.


Once the simulator is compiled, move the binary `tpm_server` into the project and run it. You should see
that the simulator is listening on ports 2321 and 2322.

To run the project, firstly install the TCG TPM2 Software Stack implementation from: https://github.com/tpm2-software/tpm2-tss
 It may be possible to use other implementations, but the `tpm2-tss` implementation is guaranteed to work.

As for the libraries, this project uses `tpm2-pytss`: https://github.com/tpm2-software/tpm2-pytss , its installation 
will work only if you installed `tpm2-tss`
