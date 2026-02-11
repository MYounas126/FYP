"""
Data loading utilities for network traffic datasets.

Supports loading CESNET-TimeSeries24, UWF-ZeekData22, and other datasets.
"""

import os
from pathlib import Path
from typing import Tuple, Optional, Dict, Any, List

import pandas as pd
import numpy as np
from loguru import logger


class DataLoader:
    """
    Universal data loader for network intrusion detection datasets.
    """

    def __init__(self, data_dir: str = "data/raw"):
        self.data_dir = Path(data_dir)

    def load_cesnet(
        self,
        aggregation: str = "1h",
        sample_frac: Optional[float] = None
    ) -> pd.DataFrame:
        """
        Load CESNET-TimeSeries24 dataset.

        Args:
            aggregation: Time aggregation level ('10m', '1h', '1d')
            sample_frac: Fraction of data to sample (for memory efficiency)

        Returns:
            DataFrame with network traffic time series
        """
        cesnet_dir = self.data_dir / "cesnet-timeseries24"

        if not cesnet_dir.exists():
            raise FileNotFoundError(
                f"CESNET dataset not found at {cesnet_dir}. "
                "Please download from https://zenodo.org/records/13382427"
            )

        logger.info(f"Loading CESNET-TimeSeries24 ({aggregation} aggregation)")

        # Load based on aggregation level
        agg_map = {"10m": "10min", "1h": "1hour", "1d": "1day"}
        agg_folder = agg_map.get(aggregation, "1hour")

        # Load IP-level data
        ip_file = cesnet_dir / agg_folder / "ip_level.parquet"
        if ip_file.exists():
            df = pd.read_parquet(ip_file)
        else:
            # Try CSV
            csv_files = list((cesnet_dir / agg_folder).glob("*.csv"))
            if csv_files:
                df = pd.concat([pd.read_csv(f) for f in csv_files])
            else:
                raise FileNotFoundError(f"No data files found in {cesnet_dir / agg_folder}")

        if sample_frac and sample_frac < 1.0:
            df = df.sample(frac=sample_frac, random_state=42)

        logger.info(f"Loaded {len(df)} records from CESNET dataset")
        return df

    def load_uwf_zeek(
        self,
        include_labels: bool = True
    ) -> pd.DataFrame:
        """
        Load UWF-ZeekData22 dataset.

        Args:
            include_labels: Include MITRE ATT&CK labels

        Returns:
            DataFrame with Zeek connection logs
        """
        uwf_dir = self.data_dir / "uwf-zeekdata22"

        if not uwf_dir.exists():
            raise FileNotFoundError(
                f"UWF dataset not found at {uwf_dir}. "
                "Please download from https://datasets.uwf.edu/"
            )

        logger.info("Loading UWF-ZeekData22 dataset")

        # Load Zeek conn logs
        parquet_files = list(uwf_dir.glob("*.parquet"))
        csv_files = list(uwf_dir.glob("*.csv"))

        if parquet_files:
            df = pd.concat([pd.read_parquet(f) for f in parquet_files])
        elif csv_files:
            df = pd.concat([pd.read_csv(f) for f in csv_files])
        else:
            raise FileNotFoundError(f"No data files found in {uwf_dir}")

        logger.info(f"Loaded {len(df)} records from UWF-ZeekData22")
        return df

    def load_custom_pcap(
        self,
        pcap_path: str,
        max_packets: int = 100000
    ) -> pd.DataFrame:
        """
        Load and parse custom PCAP file.

        Args:
            pcap_path: Path to PCAP file
            max_packets: Maximum number of packets to process

        Returns:
            DataFrame with extracted flow features
        """
        from scapy.all import rdpcap, IP, TCP, UDP

        logger.info(f"Loading PCAP: {pcap_path}")

        packets = rdpcap(pcap_path, count=max_packets)
        flows = []

        for pkt in packets:
            if IP in pkt:
                flow = {
                    "timestamp": float(pkt.time),
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                    "protocol": pkt[IP].proto,
                    "length": len(pkt),
                    "ttl": pkt[IP].ttl,
                }

                if TCP in pkt:
                    flow["src_port"] = pkt[TCP].sport
                    flow["dst_port"] = pkt[TCP].dport
                    flow["flags"] = str(pkt[TCP].flags)
                elif UDP in pkt:
                    flow["src_port"] = pkt[UDP].sport
                    flow["dst_port"] = pkt[UDP].dport

                flows.append(flow)

        df = pd.DataFrame(flows)
        logger.info(f"Extracted {len(df)} packets from PCAP")
        return df


def download_dataset(dataset_name: str, output_dir: str = "data/raw") -> None:
    """
    Download dataset from source.

    Args:
        dataset_name: Name of dataset ('cesnet', 'uwf', etc.)
        output_dir: Output directory
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if dataset_name.lower() == "cesnet":
        logger.info("Downloading CESNET-TimeSeries24...")
        logger.info("Please download manually from: https://zenodo.org/records/13382427")
        logger.info(f"Extract to: {output_path / 'cesnet-timeseries24'}")

    elif dataset_name.lower() == "uwf":
        logger.info("Downloading UWF-ZeekData22...")
        logger.info("Please download manually from: https://datasets.uwf.edu/")
        logger.info(f"Extract to: {output_path / 'uwf-zeekdata22'}")

    else:
        logger.error(f"Unknown dataset: {dataset_name}")


if __name__ == "__main__":
    # Example usage
    loader = DataLoader()

    print("\nSentinelFlow Data Loader")
    print("=" * 50)
    print("\nSupported datasets:")
    print("1. CESNET-TimeSeries24 (Time-series anomaly detection)")
    print("2. UWF-ZeekData22 (MITRE ATT&CK labeled)")
    print("\nDownload instructions:")
    download_dataset("cesnet")
    download_dataset("uwf")
