from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # MISP
    misp_url: str = "https://localhost"
    misp_key: str = "your-misp-api-key"
    misp_verifycert: bool = False

    # Wazuh
    wazuh_url: str = "https://localhost:55000"
    wazuh_user: str = "wazuh-wui"
    wazuh_password: str = "your-wazuh-password"
    wazuh_container: str = "wazuh-lab-wazuh.manager-1"
    wazuh_alerts_path: str = "/var/ossec/logs/alerts/alerts.json"

    # Suricata
    suricata_container: str = "suricata-mirror"
    suricata_eve_path: str = "/var/log/suricata/eve.json"


    class Config:
        env_file = "backend/.env"

settings = Settings()
