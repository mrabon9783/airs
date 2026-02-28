from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    database_url: str = Field("postgresql+psycopg2://airs:airs@postgres:5432/airs")
    tenant_id: str = Field("")
    client_id: str = Field("")
    client_secret: str = Field("")
    graph_scope: str = Field("https://graph.microsoft.com/.default")
    graph_base_url: str = Field("https://graph.microsoft.com")
    use_beta_signin_activity: bool = Field(False)
    stale_days_threshold: int = Field(90)

    class Config:
        env_file = ".env"
        env_prefix = "AIRS_"


settings = Settings()
