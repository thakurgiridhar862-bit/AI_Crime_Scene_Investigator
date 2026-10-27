import pandas as pd
import io
from typing import Union, Dict, Any, List

def _find_column(df: pd.DataFrame, candidates: List[str], default_name: str) -> str:
    """Finds matching column case-insensitively from a list of candidates."""
    lower_cols = {c.lower(): c for c in df.columns}
    for cand in candidates:
        if cand.lower() in lower_cols:
            return lower_cols[cand.lower()]
    return default_name

class ForensicParser:
    """Ultra-resilient multi-source forensic log parser supporting all standard SIEM formats."""

    @staticmethod
    def _read_to_df(data: Union[str, bytes, io.BytesIO, pd.DataFrame]) -> pd.DataFrame:
        if isinstance(data, pd.DataFrame):
            return data.copy()
        if isinstance(data, bytes):
            return pd.read_csv(io.BytesIO(data))
        if isinstance(data, io.BytesIO):
            data.seek(0)
            return pd.read_csv(data)
        if isinstance(data, str):
            return pd.read_csv(data)
        raise ValueError(f"Cannot parse input of type {type(data)}")

    @classmethod
    def parse_login_logs(cls, data: Union[str, bytes, io.BytesIO, pd.DataFrame]) -> pd.DataFrame:
        df = cls._read_to_df(data)

        # Flexible column resolution
        user_col = _find_column(df, ["user_email", "user_id", "user", "username", "actor"], "user_id")
        ip_col = _find_column(df, ["src_ip", "ip_address", "ip", "source_ip", "client_ip"], "ip_address")
        status_col = _find_column(df, ["auth_status", "status", "outcome", "result"], "status")
        country_col = _find_column(df, ["geo_country", "country", "location"], "country")
        event_col = _find_column(df, ["event_type", "action", "auth_protocol", "event"], "event_type")
        time_col = _find_column(df, ["timestamp", "time", "datetime", "date"], "timestamp")

        if user_col in df.columns and user_col != "user_id":
            df["user_id"] = df[user_col]
        elif "user_id" not in df.columns:
            df["user_id"] = "unknown_user"

        if ip_col in df.columns and ip_col != "ip_address":
            df["ip_address"] = df[ip_col]
        elif "ip_address" not in df.columns:
            df["ip_address"] = "127.0.0.1"

        if status_col in df.columns and status_col != "status":
            df["status"] = df[status_col]
        elif "status" not in df.columns:
            df["status"] = "SUCCESS"

        if country_col in df.columns and country_col != "country":
            df["country"] = df[country_col]

        if event_col in df.columns and event_col != "event_type":
            df["event_type"] = df[event_col]
        elif "event_type" not in df.columns:
            df["event_type"] = "LOGIN_SUCCESS"

        df["timestamp"] = pd.to_datetime(df[time_col].astype(str).str.replace(" UTC", ""), errors="coerce")
        df["timestamp"] = df["timestamp"].fillna(pd.Timestamp.utcnow())

        return df.sort_values("timestamp").reset_index(drop=True)

    @classmethod
    def parse_file_logs(cls, data: Union[str, bytes, io.BytesIO, pd.DataFrame]) -> pd.DataFrame:
        df = cls._read_to_df(data)

        user_col = _find_column(df, ["user_email", "user_id", "user", "username", "actor"], "user_id")
        path_col = _find_column(df, ["file_path", "filename", "target_file", "path", "object_name"], "file_path")
        action_col = _find_column(df, ["access_type", "action", "event_type", "operation"], "action")
        bytes_col = _find_column(df, ["bytes_transferred", "bytes_read", "file_size_bytes", "bytes", "size"], "bytes_read")
        time_col = _find_column(df, ["timestamp", "time", "datetime", "date"], "timestamp")

        if user_col in df.columns and user_col != "user_id":
            df["user_id"] = df[user_col]
        elif "user_id" not in df.columns:
            df["user_id"] = "unknown_user"

        if path_col in df.columns and path_col != "file_path":
            df["file_path"] = df[path_col]
        elif "file_path" not in df.columns:
            df["file_path"] = "/shares/unknown_file"

        if action_col in df.columns and action_col != "action":
            df["action"] = df[action_col]
        elif "action" not in df.columns:
            df["action"] = "READ"

        if bytes_col in df.columns and bytes_col != "bytes_read":
            df["bytes_read"] = df[bytes_col]
        elif "bytes_read" not in df.columns:
            df["bytes_read"] = 0

        df["bytes_read"] = pd.to_numeric(df["bytes_read"], errors="coerce").fillna(0).astype(int)
        df["timestamp"] = pd.to_datetime(df[time_col].astype(str).str.replace(" UTC", ""), errors="coerce")
        df["timestamp"] = df["timestamp"].fillna(pd.Timestamp.utcnow())

        return df.sort_values("timestamp").reset_index(drop=True)

    @classmethod
    def parse_network_logs(cls, data: Union[str, bytes, io.BytesIO, pd.DataFrame]) -> pd.DataFrame:
        df = cls._read_to_df(data)

        src_col = _find_column(df, ["src_ip", "source_ip", "src", "client_ip"], "source_ip")
        dest_col = _find_column(df, ["dest_ip", "destination_ip", "dest", "target_ip", "remote_ip"], "destination_ip")
        bytes_col = _find_column(df, ["bytes_sent", "bytes_out", "bytes_transferred", "bytes", "size"], "bytes_sent")
        time_col = _find_column(df, ["timestamp", "time", "datetime", "date"], "timestamp")
        port_col = _find_column(df, ["dest_port", "destination_port", "port", "dst_port"], "dest_port")

        if src_col in df.columns and src_col != "source_ip":
            df["source_ip"] = df[src_col]
        elif "source_ip" not in df.columns:
            df["source_ip"] = "10.0.0.1"

        if dest_col in df.columns and dest_col != "destination_ip":
            df["destination_ip"] = df[dest_col]
        elif "destination_ip" not in df.columns:
            df["destination_ip"] = "0.0.0.0"

        if bytes_col in df.columns and bytes_col != "bytes_sent":
            df["bytes_sent"] = df[bytes_col]
        elif "bytes_sent" not in df.columns:
            df["bytes_sent"] = 0

        if port_col in df.columns and port_col != "dest_port":
            df["dest_port"] = df[port_col]
        elif "dest_port" not in df.columns:
            df["dest_port"] = 443

        df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors="coerce").fillna(0).astype(int)
        df["timestamp"] = pd.to_datetime(df[time_col].astype(str).str.replace(" UTC", ""), errors="coerce")
        df["timestamp"] = df["timestamp"].fillna(pd.Timestamp.utcnow())

        return df.sort_values("timestamp").reset_index(drop=True)
