//! Script for multi-agent (two-signer) E2E tests.
//! Signature: main(sender: &signer, _secondary: &signer, recipient: address, amount: u64)
//! Transfers `amount` APT from sender to recipient; secondary signer is required but unused.

script {
    use aptos_framework::aptos_account;

    fun main(
        sender: &signer,
        _secondary: &signer,
        recipient: address,
        amount: u64,
    ) {
        aptos_account::transfer(sender, recipient, amount);
    }
}
