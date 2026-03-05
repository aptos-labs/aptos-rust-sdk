//! Script for single-signer (normal) script E2E tests.
//! Signature: main(sender: &signer, recipient: address, amount: u64)
//! Transfers `amount` APT from sender to recipient.

script {
    use aptos_framework::aptos_account;

    fun main(sender: &signer, recipient: address, amount: u64) {
        aptos_account::transfer(sender, recipient, amount);
    }
}
