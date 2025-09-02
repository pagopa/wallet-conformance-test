import { loadAttestation } from "./logic";

loadAttestation({
	wallet_id: "wallet_cli_instance",
	wallet_name: "CEN TC Wallet CLI",
	wallet_provider_base_url: "https://wallet-provider.example.it",
	wallet_attestations_storage_path: "./data/wallet_attestations",
	credentials_storage_path: "./data/credentials",
	backup_storage_path: "./data/backup"
});