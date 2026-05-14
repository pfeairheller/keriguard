# -*- encoding: utf-8 -*-
"""
Unit tests for keriguard.core.wireguarding module
"""

import base64
from datetime import datetime
from io import StringIO

import pytest
from keri.app import habbing

from keriguard.core.wireguarding import (
    # Exceptions
    KeyGenerationError,
    ValidationError,
    ConfigParseError,
    # KERI Integration
    KERIKeyGenerator,
    # Data Models
    WireguardInterface,
    WireguardPeer,
    WireguardConfig,
    # Validators
    InterfaceValidator,
    PeerValidator,
    ConfigValidator,
    # File I/O
    WireguardConfigParser,
    WireguardConfigWriter,
    # Main API
    WireguardConfigManager,
)

# ============================================================================
# Test KeriKeyGenerator
# ============================================================================


class TestKeriKeyGenerator:
    """Test KERI key generation functionality."""

    def test_generate_keypair(self):
        """Test generating a Wireguard keypair with KERI tracking."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, public_key, keri_signer = keygen.generate_keypair()

            # Verify keys are base64 strings
            assert isinstance(private_key, str)
            assert isinstance(public_key, str)

            # Verify keys decode to 32 bytes
            private_bytes = base64.b64decode(private_key)
            public_bytes = base64.b64decode(public_key)
            assert len(private_bytes) == 32
            assert len(public_bytes) == 32

            # Verify KERI signer exists
            assert keri_signer is not None
            assert hasattr(keri_signer, "qb64")
            assert hasattr(keri_signer, "verfer")

    def test_generate_preshared_key(self):
        """Test generating a preshared key."""
        psk = KERIKeyGenerator.generate_preshared_key()

        # Verify PSK is base64 string
        assert isinstance(psk, str)

        # Verify PSK decodes to 32 bytes
        psk_bytes = base64.b64decode(psk)
        assert len(psk_bytes) == 32

    def test_derive_public_key(self):
        """Test deriving public key from private key."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, expected_public_key, _ = keygen.generate_keypair()

            # Derive public key
            derived_public_key = KERIKeyGenerator._derive_public_key(private_key)

            # Verify derived key matches expected
            assert derived_public_key == expected_public_key

    def test_derive_public_key_invalid(self):
        """Test deriving public key with invalid private key."""
        with pytest.raises(KeyGenerationError):
            KERIKeyGenerator._derive_public_key("invalid_key")


# ============================================================================
# Test Validators
# ============================================================================


class TestInterfaceValidator:
    """Test interface validation."""

    def test_validate_private_key_valid(self):
        """Test validating a valid private key."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            # Should not raise
            InterfaceValidator.validate_private_key(private_key)

    def test_validate_private_key_empty(self):
        """Test validating empty private key."""
        with pytest.raises(ValidationError, match="Private key is required"):
            InterfaceValidator.validate_private_key("")

    def test_validate_private_key_wrong_length(self):
        """Test validating private key with wrong length."""
        short_key = base64.b64encode(b"short").decode("ascii")
        with pytest.raises(ValidationError, match="must be 32 bytes"):
            InterfaceValidator.validate_private_key(short_key)

    def test_validate_private_key_all_zeros(self):
        """Test validating all-zero private key."""
        zero_key = base64.b64encode(b"\x00" * 32).decode("ascii")
        with pytest.raises(ValidationError, match="cannot be all zeros"):
            InterfaceValidator.validate_private_key(zero_key)

    def test_validate_address_valid_ipv4(self):
        """Test validating valid IPv4 address."""
        InterfaceValidator.validate_address("10.0.0.1/24")
        InterfaceValidator.validate_address("192.168.1.1/32")

    def test_validate_address_valid_ipv6(self):
        """Test validating valid IPv6 address."""
        InterfaceValidator.validate_address("fd00::1/64")
        InterfaceValidator.validate_address("2001:db8::1/128")

    def test_validate_address_missing_prefix(self):
        """Test validating address without CIDR prefix."""
        with pytest.raises(ValidationError, match="must include CIDR prefix"):
            InterfaceValidator.validate_address("10.0.0.1")

    def test_validate_address_invalid(self):
        """Test validating invalid address."""
        with pytest.raises(ValidationError, match="Invalid address format"):
            InterfaceValidator.validate_address("not.an.ip/24")

    def test_validate_addresses_empty(self):
        """Test validating empty address list."""
        with pytest.raises(ValidationError, match="At least one address is required"):
            InterfaceValidator.validate_addresses([])

    def test_validate_listen_port_valid(self):
        """Test validating valid listen port."""
        InterfaceValidator.validate_listen_port(51820)
        InterfaceValidator.validate_listen_port(1)
        InterfaceValidator.validate_listen_port(65535)
        InterfaceValidator.validate_listen_port(None)

    def test_validate_listen_port_out_of_range(self):
        """Test validating out-of-range port."""
        with pytest.raises(ValidationError, match="must be between 1 and 65535"):
            InterfaceValidator.validate_listen_port(0)

        with pytest.raises(ValidationError, match="must be between 1 and 65535"):
            InterfaceValidator.validate_listen_port(65536)

    def test_validate_dns_valid(self):
        """Test validating valid DNS servers."""
        InterfaceValidator.validate_dns(["8.8.8.8", "1.1.1.1"])
        InterfaceValidator.validate_dns(["dns.google.com"])
        InterfaceValidator.validate_dns(None)

    def test_validate_dns_invalid(self):
        """Test validating invalid DNS server."""
        with pytest.raises(ValidationError, match="Invalid DNS server format"):
            InterfaceValidator.validate_dns(["not_a_valid_dns!"])

    def test_validate_mtu_valid(self):
        """Test validating valid MTU."""
        InterfaceValidator.validate_mtu(1420)
        InterfaceValidator.validate_mtu(1280)
        InterfaceValidator.validate_mtu(9000)
        InterfaceValidator.validate_mtu(None)

    def test_validate_mtu_out_of_range(self):
        """Test validating out-of-range MTU."""
        with pytest.raises(ValidationError, match="must be between 1280 and 9000"):
            InterfaceValidator.validate_mtu(1279)

        with pytest.raises(ValidationError, match="must be between 1280 and 9000"):
            InterfaceValidator.validate_mtu(9001)


class TestPeerValidator:
    """Test peer validation."""

    def test_validate_public_key_valid(self):
        """Test validating valid public key."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            _, public_key, _ = keygen.generate_keypair()
            PeerValidator.validate_public_key(public_key)

    def test_validate_public_key_empty(self):
        """Test validating empty public key."""
        with pytest.raises(ValidationError, match="Public key is required"):
            PeerValidator.validate_public_key("")

    def test_validate_public_key_wrong_length(self):
        """Test validating public key with wrong length."""
        short_key = base64.b64encode(b"short").decode("ascii")
        with pytest.raises(ValidationError, match="must be 32 bytes"):
            PeerValidator.validate_public_key(short_key)

    def test_validate_allowed_ips_valid(self):
        """Test validating valid allowed IPs."""
        PeerValidator.validate_allowed_ips(["10.0.0.2/32"])
        PeerValidator.validate_allowed_ips(["10.0.0.0/24", "192.168.1.0/24"])
        PeerValidator.validate_allowed_ips(["0.0.0.0/0"])  # Allow all

    def test_validate_allowed_ips_empty(self):
        """Test validating empty allowed IPs."""
        with pytest.raises(
            ValidationError, match="At least one allowed IP is required"
        ):
            PeerValidator.validate_allowed_ips([])

    def test_validate_allowed_ips_invalid(self):
        """Test validating invalid allowed IP."""
        with pytest.raises(ValidationError, match="Invalid allowed IP format"):
            PeerValidator.validate_allowed_ips(["not.an.ip/24"])

    def test_validate_endpoint_valid(self):
        """Test validating valid endpoints."""
        PeerValidator.validate_endpoint("192.0.2.1:51820")
        PeerValidator.validate_endpoint("example.com:51820")
        PeerValidator.validate_endpoint("[2001:db8::1]:51820")
        PeerValidator.validate_endpoint(None)

    def test_validate_endpoint_invalid_format(self):
        """Test validating invalid endpoint format."""
        with pytest.raises(ValidationError, match="Invalid endpoint format"):
            PeerValidator.validate_endpoint("192.0.2.1")  # Missing port

        with pytest.raises(ValidationError, match="Invalid endpoint format"):
            PeerValidator.validate_endpoint("invalid:format:here")

    def test_validate_endpoint_invalid_port(self):
        """Test validating endpoint with invalid port."""
        with pytest.raises(ValidationError, match="port must be between 1 and 65535"):
            PeerValidator.validate_endpoint("example.com:0")

        with pytest.raises(ValidationError, match="port must be between 1 and 65535"):
            PeerValidator.validate_endpoint("example.com:99999")

    def test_validate_persistent_keepalive_valid(self):
        """Test validating valid keepalive."""
        PeerValidator.validate_persistent_keepalive(25)
        PeerValidator.validate_persistent_keepalive(1)
        PeerValidator.validate_persistent_keepalive(300)
        PeerValidator.validate_persistent_keepalive(None)

    def test_validate_persistent_keepalive_out_of_range(self):
        """Test validating out-of-range keepalive."""
        with pytest.raises(ValidationError, match="must be between 1 and 300"):
            PeerValidator.validate_persistent_keepalive(0)

        with pytest.raises(ValidationError, match="must be between 1 and 300"):
            PeerValidator.validate_persistent_keepalive(301)

    def test_validate_preshared_key_valid(self):
        """Test validating valid preshared key."""
        psk = KERIKeyGenerator.generate_preshared_key()
        PeerValidator.validate_preshared_key(psk)
        PeerValidator.validate_preshared_key(None)

    def test_validate_preshared_key_wrong_length(self):
        """Test validating preshared key with wrong length."""
        short_key = base64.b64encode(b"short").decode("ascii")
        with pytest.raises(ValidationError, match="must be 32 bytes"):
            PeerValidator.validate_preshared_key(short_key)


class TestConfigValidator:
    """Test configuration validation."""

    def test_validate_config_valid(self):
        """Test validating valid configuration."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, keri_signer = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key,
                address=["10.0.0.1/24"],
                keri_signer_qb64=keri_signer.qb64,
            )

            _, pub_key, _ = keygen.generate_keypair()
            peer = WireguardPeer(
                public_key=pub_key,
                allowed_ips=["10.0.0.2/32"],
            )

            config = WireguardConfig(interface=interface, peers=[peer])
            ConfigValidator.validate_config(config)

    def test_validate_config_duplicate_peer_keys(self):
        """Test validating config with duplicate peer keys."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, keri_signer = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key,
                address=["10.0.0.1/24"],
                keri_signer_qb64=keri_signer.qb64,
            )

            _, pub_key, _ = keygen.generate_keypair()
            peer1 = WireguardPeer(public_key=pub_key, allowed_ips=["10.0.0.2/32"])
            peer2 = WireguardPeer(public_key=pub_key, allowed_ips=["10.0.0.3/32"])

            config = WireguardConfig(interface=interface, peers=[peer1, peer2])

            with pytest.raises(ValidationError, match="Duplicate peer public key"):
                ConfigValidator.validate_config(config)


# ============================================================================
# Test Data Models
# ============================================================================


class TestWireguardInterface:
    """Test WireguardInterface dataclass."""

    def test_create_minimal_interface(self):
        """Test creating interface with minimal required fields."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key,
                address=["10.0.0.1/24"],
            )

            assert interface.private_key == private_key
            assert interface.address == ["10.0.0.1/24"]
            assert interface.listen_port is None
            assert interface.dns is None

    def test_create_full_interface(self):
        """Test creating interface with all fields."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, keri_signer = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key,
                address=["10.0.0.1/24", "fd00::1/64"],
                listen_port=51820,
                dns=["8.8.8.8", "1.1.1.1"],
                mtu=1420,
                table="auto",
                pre_up="echo 'Starting WireGuard'",
                post_up="iptables -A FORWARD -i wg0 -j ACCEPT",
                pre_down="echo 'Stopping WireGuard'",
                post_down="iptables -D FORWARD -i wg0 -j ACCEPT",
                keri_signer_qb64=keri_signer.qb64,
            )

            assert interface.listen_port == 51820
            assert interface.dns == ["8.8.8.8", "1.1.1.1"]
            assert interface.mtu == 1420
            assert interface.keri_signer_qb64 == keri_signer.qb64

    def test_interface_validation_on_creation(self):
        """Test that validation happens on interface creation."""
        with pytest.raises(ValidationError):
            WireguardInterface(
                private_key="invalid_key",
                address=["10.0.0.1/24"],
            )


class TestWireguardPeer:
    """Test WireguardPeer dataclass."""

    def test_create_minimal_peer(self):
        """Test creating peer with minimal required fields."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            _, public_key, _ = keygen.generate_keypair()
            peer = WireguardPeer(
                public_key=public_key,
                allowed_ips=["10.0.0.2/32"],
            )

            assert peer.public_key == public_key
            assert peer.allowed_ips == ["10.0.0.2/32"]
            assert peer.endpoint is None
            assert peer.persistent_keepalive is None

    def test_create_full_peer(self):
        """Test creating peer with all fields."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            _, public_key, keri_signer = keygen.generate_keypair()
            psk = KERIKeyGenerator.generate_preshared_key()

            peer = WireguardPeer(
                public_key=public_key,
                allowed_ips=["10.0.0.2/32", "192.168.1.0/24"],
                endpoint="192.0.2.1:51820",
                persistent_keepalive=25,
                preshared_key=psk,
                keri_verfer_qb64=keri_signer.verfer.qb64,
                peer_name="client-1",
            )

            assert peer.endpoint == "192.0.2.1:51820"
            assert peer.persistent_keepalive == 25
            assert peer.preshared_key == psk
            assert peer.peer_name == "client-1"

    def test_peer_validation_on_creation(self):
        """Test that validation happens on peer creation."""
        with pytest.raises(ValidationError):
            WireguardPeer(
                public_key="invalid_key",
                allowed_ips=["10.0.0.2/32"],
            )


class TestWireguardConfig:
    """Test WireguardConfig dataclass."""

    def test_create_config(self):
        """Test creating a configuration."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key,
                address=["10.0.0.1/24"],
            )

            config = WireguardConfig(
                interface=interface,
                config_name="test-config",
                description="Test configuration",
            )

            assert config.interface == interface
            assert config.config_name == "test-config"
            assert config.description == "Test configuration"
            assert isinstance(config.created_at, datetime)
            assert isinstance(config.modified_at, datetime)

    def test_add_peer(self):
        """Test adding a peer to configuration."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key, address=["10.0.0.1/24"]
            )
            config = WireguardConfig(interface=interface)

            _, public_key, _ = keygen.generate_keypair()
            peer = WireguardPeer(public_key=public_key, allowed_ips=["10.0.0.2/32"])

            original_modified = config.modified_at
            config.add_peer(peer)

            assert len(config.peers) == 1
            assert config.peers[0] == peer
            assert original_modified is not None
            assert config.modified_at > original_modified

    def test_add_duplicate_peer(self):
        """Test adding duplicate peer raises error."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key, address=["10.0.0.1/24"]
            )
            config = WireguardConfig(interface=interface)

            _, public_key, _ = keygen.generate_keypair()
            peer1 = WireguardPeer(public_key=public_key, allowed_ips=["10.0.0.2/32"])
            peer2 = WireguardPeer(public_key=public_key, allowed_ips=["10.0.0.3/32"])

            config.add_peer(peer1)

            with pytest.raises(ValidationError, match="already exists"):
                config.add_peer(peer2)

    def test_remove_peer(self):
        """Test removing a peer from configuration."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key, address=["10.0.0.1/24"]
            )
            config = WireguardConfig(interface=interface)

            _, public_key, _ = keygen.generate_keypair()
            peer = WireguardPeer(public_key=public_key, allowed_ips=["10.0.0.2/32"])
            config.add_peer(peer)

            assert len(config.peers) == 1

            result = config.remove_peer(public_key)

            assert result is True
            assert len(config.peers) == 0

    def test_remove_nonexistent_peer(self):
        """Test removing nonexistent peer returns False."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key, address=["10.0.0.1/24"]
            )
            config = WireguardConfig(interface=interface)

            _, public_key, _ = keygen.generate_keypair()

            result = config.remove_peer(public_key)

            assert result is False

    def test_get_peer(self):
        """Test getting a peer by public key."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key, address=["10.0.0.1/24"]
            )
            config = WireguardConfig(interface=interface)

            _, public_key, _ = keygen.generate_keypair()
            peer = WireguardPeer(public_key=public_key, allowed_ips=["10.0.0.2/32"])
            config.add_peer(peer)

            found_peer = config.get_peer(public_key)

            assert found_peer == peer

    def test_get_nonexistent_peer(self):
        """Test getting nonexistent peer returns None."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key, address=["10.0.0.1/24"]
            )
            config = WireguardConfig(interface=interface)

            _, public_key, _ = keygen.generate_keypair()

            found_peer = config.get_peer(public_key)

            assert found_peer is None


# ============================================================================
# Test File I/O
# ============================================================================


class TestWireguardConfigParser:
    """Test configuration file parsing."""

    def test_parse_minimal_config(self):
        """Test parsing minimal configuration."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            _, public_key, _ = keygen.generate_keypair()

            conf_text = f"""[Interface]
PrivateKey = {private_key}
Address = 10.0.0.1/24

[Peer]
PublicKey = {public_key}
AllowedIPs = 10.0.0.2/32
"""

            config = WireguardConfigParser.parse_stream(StringIO(conf_text))

            assert config.interface.private_key == private_key
            assert config.interface.address == ["10.0.0.1/24"]
            assert len(config.peers) == 1
            assert config.peers[0].public_key == public_key
            assert config.peers[0].allowed_ips == ["10.0.0.2/32"]

    def test_parse_full_config(self):
        """Test parsing full configuration."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            _, public_key, _ = keygen.generate_keypair()

            conf_text = f"""# Test configuration
[Interface]
PrivateKey = {private_key}
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
DNS = 8.8.8.8, 1.1.1.1
MTU = 1420

[Peer]
PublicKey = {public_key}
AllowedIPs = 10.0.0.2/32, 192.168.1.0/24
Endpoint = 192.0.2.1:51820
PersistentKeepalive = 25
"""

            config = WireguardConfigParser.parse_stream(StringIO(conf_text))

            assert config.interface.listen_port == 51820
            assert config.interface.dns == ["8.8.8.8", "1.1.1.1"]
            assert config.interface.mtu == 1420
            assert config.peers[0].endpoint == "192.0.2.1:51820"
            assert config.peers[0].persistent_keepalive == 25

    def test_parse_multiple_peers(self):
        """Test parsing configuration with multiple peers."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            _, pub_key1, _ = keygen.generate_keypair()
            _, pub_key2, _ = keygen.generate_keypair()

            conf_text = f"""[Interface]
PrivateKey = {private_key}
Address = 10.0.0.1/24

[Peer]
PublicKey = {pub_key1}
AllowedIPs = 10.0.0.2/32

[Peer]
PublicKey = {pub_key2}
AllowedIPs = 10.0.0.3/32
"""

            config = WireguardConfigParser.parse_stream(StringIO(conf_text))

            assert len(config.peers) == 2
            assert config.peers[0].public_key == pub_key1
            assert config.peers[1].public_key == pub_key2

    def test_parse_missing_interface(self):
        """Test parsing config without interface section."""
        conf_text = """[Peer]
PublicKey = test
AllowedIPs = 10.0.0.2/32
"""

        with pytest.raises(
            ConfigParseError, match="must have an \\[Interface\\] section"
        ):
            WireguardConfigParser.parse_stream(StringIO(conf_text))

    def test_parse_missing_private_key(self):
        """Test parsing interface without private key."""
        conf_text = """[Interface]
Address = 10.0.0.1/24
"""

        with pytest.raises(ConfigParseError, match="missing PrivateKey"):
            WireguardConfigParser.parse_stream(StringIO(conf_text))

    def test_parse_file(self, tmp_path):
        """Test parsing from file."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            _, public_key, _ = keygen.generate_keypair()

            conf_path = tmp_path / "test.conf"
            conf_path.write_text(f"""[Interface]
PrivateKey = {private_key}
Address = 10.0.0.1/24

[Peer]
PublicKey = {public_key}
AllowedIPs = 10.0.0.2/32
""")

            config = WireguardConfigParser.parse_file(conf_path)

            assert config.config_name == "test"
            assert config.interface.private_key == private_key


class TestWireguardConfigWriter:
    """Test configuration file writing."""

    def test_write_minimal_config(self):
        """Test writing minimal configuration."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key, address=["10.0.0.1/24"]
            )

            _, public_key, _ = keygen.generate_keypair()
            peer = WireguardPeer(public_key=public_key, allowed_ips=["10.0.0.2/32"])

            config = WireguardConfig(interface=interface, peers=[peer])

            output = WireguardConfigWriter.write_stream(config)

            assert "[Interface]" in output
            assert f"PrivateKey = {private_key}" in output
            assert "Address = 10.0.0.1/24" in output
            assert "[Peer]" in output
            assert f"PublicKey = {public_key}" in output
            assert "AllowedIPs = 10.0.0.2/32" in output

    def test_write_full_config(self):
        """Test writing full configuration."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, keri_signer = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key,
                address=["10.0.0.1/24", "fd00::1/64"],
                listen_port=51820,
                dns=["8.8.8.8", "1.1.1.1"],
                mtu=1420,
            )

            _, public_key, keri_signer2 = keygen.generate_keypair()
            peer = WireguardPeer(
                public_key=public_key,
                allowed_ips=["10.0.0.2/32"],
                endpoint="192.0.2.1:51820",
                persistent_keepalive=25,
                peer_name="client-1",
                keri_verfer_qb64=keri_signer2.verfer.qb64,
            )

            config = WireguardConfig(
                interface=interface,
                peers=[peer],
                config_name="test-config",
                description="Test configuration",
            )

            output = WireguardConfigWriter.write_stream(config)

            assert "# Configuration: test-config" in output
            assert "# Description: Test configuration" in output
            assert "ListenPort = 51820" in output
            assert "DNS = 8.8.8.8, 1.1.1.1" in output
            assert "MTU = 1420" in output
            assert "# Name: client-1" in output
            assert "Endpoint = 192.0.2.1:51820" in output
            assert "PersistentKeepalive = 25" in output

    def test_write_file(self, tmp_path):
        """Test writing to file."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, _ = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key, address=["10.0.0.1/24"]
            )
            config = WireguardConfig(interface=interface)

            conf_path = tmp_path / "test.conf"
            WireguardConfigWriter.write_file(config, conf_path)

            assert conf_path.exists()
            content = conf_path.read_text()
            assert "[Interface]" in content
            assert f"PrivateKey = {private_key}" in content

    def test_roundtrip(self):
        """Test that parse(write(config)) == config."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            keygen = KERIKeyGenerator(hab=hab)
            private_key, _, keri_signer = keygen.generate_keypair()
            interface = WireguardInterface(
                private_key=private_key,
                address=["10.0.0.1/24"],
                listen_port=51820,
                keri_signer_qb64=keri_signer.qb64,
            )

            _, public_key, _ = keygen.generate_keypair()
            peer = WireguardPeer(
                public_key=public_key,
                allowed_ips=["10.0.0.2/32"],
                endpoint="192.0.2.1:51820",
            )

            config = WireguardConfig(interface=interface, peers=[peer])

            # Write to string
            output = WireguardConfigWriter.write_stream(config)

            # Parse back
            parsed = WireguardConfigParser.parse_stream(StringIO(output))

            # Compare (metadata like timestamps won't match)
            assert parsed.interface.private_key == config.interface.private_key
            assert parsed.interface.address == config.interface.address
            assert parsed.interface.listen_port == config.interface.listen_port
            assert len(parsed.peers) == len(config.peers)
            assert parsed.peers[0].public_key == config.peers[0].public_key
            assert parsed.peers[0].allowed_ips == config.peers[0].allowed_ips
            assert parsed.peers[0].endpoint == config.peers[0].endpoint


# ============================================================================
# Test Main API
# ============================================================================


class TestWireguardConfigManager:
    """Test main configuration manager API."""

    def test_generate_config(self):
        """Test generating a new configuration."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            manager = WireguardConfigManager(hab=hab)

            config = manager.generate_config(
                address=["10.0.0.1/24"],
                listen_port=51820,
                dns=["8.8.8.8"],
                config_name="test-server",
                description="Test server configuration",
            )

            assert config is not None
            assert config.interface.address == ["10.0.0.1/24"]
            assert config.interface.listen_port == 51820
            assert config.interface.dns == ["8.8.8.8"]
            assert config.config_name == "test-server"
            assert config.description == "Test server configuration"
            assert config.interface.keri_signer_qb64 is not None

    def test_add_peer_to_config(self):
        """Test adding a peer to configuration."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            manager = WireguardConfigManager(hab=hab)
            config = manager.generate_config(address=["10.0.0.1/24"])

            peer = manager.add_peer_to_config(
                config,
                allowed_ips=["10.0.0.2/32"],
                endpoint="192.0.2.1:51820",
                persistent_keepalive=25,
                peer_name="client-1",
            )

            assert peer is not None
            assert len(config.peers) == 1
            assert config.peers[0] == peer
            assert peer.allowed_ips == ["10.0.0.2/32"]
            assert peer.endpoint == "192.0.2.1:51820"
            assert peer.persistent_keepalive == 25
            assert peer.peer_name == "client-1"
            assert peer.keri_verfer_qb64 is not None

    def test_add_peer_with_public_key(self):
        """Test adding a peer with provided public key."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            manager = WireguardConfigManager(hab=hab)
            config = manager.generate_config(address=["10.0.0.1/24"])

            keygen = KERIKeyGenerator(hab=hab)
            _, public_key, _ = keygen.generate_keypair()

            peer = manager.add_peer_to_config(
                config,
                allowed_ips=["10.0.0.2/32"],
                public_key=public_key,
            )

            assert peer.public_key == public_key
            assert peer.keri_verfer_qb64 is None  # No KERI tracking when key provided

    def test_remove_peer_from_config(self):
        """Test removing a peer from configuration."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            manager = WireguardConfigManager(hab=hab)
            config = manager.generate_config(address=["10.0.0.1/24"])

            peer = manager.add_peer_to_config(config, allowed_ips=["10.0.0.2/32"])

            result = manager.remove_peer_from_config(config, peer.public_key)

            assert result is True
            assert len(config.peers) == 0

    def test_update_interface_port(self):
        """Test updating interface port."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            manager = WireguardConfigManager(hab=hab)
            config = manager.generate_config(address=["10.0.0.1/24"], listen_port=51820)

            manager.update_interface_port(config, 51821)

            assert config.interface.listen_port == 51821

    def test_validate_config(self):
        """Test validating a configuration."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            manager = WireguardConfigManager(hab=hab)
            config = manager.generate_config(address=["10.0.0.1/24"])

            # Should not raise
            result = manager.validate_config(config)

            assert result is True

    def test_load_and_save_config(self, tmp_path):
        """Test saving and loading a configuration."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            manager = WireguardConfigManager(hab=hab)

            # Generate configuration
            config = manager.generate_config(
                address=["10.0.0.1/24"],
                listen_port=51820,
                config_name="test-config",
            )

            manager.add_peer_to_config(
                config,
                allowed_ips=["10.0.0.2/32"],
                endpoint="192.0.2.1:51820",
            )

            # Save to file
            conf_path = tmp_path / "test.conf"
            manager.save_config(config, conf_path)

            assert conf_path.exists()

            # Load from file
            loaded = manager.load_config(conf_path)

            assert loaded.interface.address == config.interface.address
            assert loaded.interface.listen_port == config.interface.listen_port
            assert len(loaded.peers) == 1
            assert loaded.peers[0].allowed_ips == config.peers[0].allowed_ips

    def test_save_config_with_backup(self, tmp_path):
        """Test saving configuration with backup."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            manager = WireguardConfigManager(hab=hab)
            conf_path = tmp_path / "test.conf"

            # Create initial config
            config1 = manager.generate_config(address=["10.0.0.1/24"])
            manager.save_config(config1, conf_path, backup=False)

            # Save modified config with backup
            config2 = manager.generate_config(address=["10.0.0.2/24"])
            manager.save_config(config2, conf_path, backup=True)

            # Check backup was created
            backup_path = conf_path.with_suffix(".conf.bak")
            assert backup_path.exists()

            # Verify backup contains original content
            backup_config = manager.load_config(backup_path)
            assert backup_config.interface.address == ["10.0.0.1/24"]

    def test_generate_peer_keys(self):
        """Test generating peer keypair."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            manager = WireguardConfigManager(hab=hab)

            private_key, public_key = manager.generate_peer_keys()

            assert isinstance(private_key, str)
            assert isinstance(public_key, str)

            # Verify keys are valid
            private_bytes = base64.b64decode(private_key)
            public_bytes = base64.b64decode(public_key)
            assert len(private_bytes) == 32
            assert len(public_bytes) == 32

    def test_full_workflow(self, tmp_path):
        """Test complete workflow: generate, add peers, save, load, validate."""
        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            manager = WireguardConfigManager(hab=hab)

            # 1. Generate configuration
            config = manager.generate_config(
                address=["10.0.0.1/24"],
                listen_port=51820,
                dns=["8.8.8.8", "1.1.1.1"],
                mtu=1420,
                config_name="vpn-server",
                description="VPN Server Configuration",
            )

            # 2. Add multiple peers (using explicit keys to avoid duplicates)
            # Generate unique keys for each peer
            keygen = KERIKeyGenerator(hab=hab)
            _, pub_key1, _ = keygen.generate_keypair()

        # Create separate hab for peer2 to get a different key
        with habbing.openHab(name="peer2", temp=True) as (hby2, hab2):
            keygen2 = KERIKeyGenerator(hab=hab2)
            _, pub_key2, _ = keygen2.generate_keypair()

        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            manager = WireguardConfigManager(hab=hab)

            # Re-generate configuration in new context
            config = manager.generate_config(
                address=["10.0.0.1/24"],
                listen_port=51820,
                dns=["8.8.8.8", "1.1.1.1"],
                mtu=1420,
                config_name="vpn-server",
                description="VPN Server Configuration",
            )

            manager.add_peer_to_config(
                config,
                allowed_ips=["10.0.0.2/32"],
                endpoint="192.0.2.1:51820",
                persistent_keepalive=25,
                peer_name="client-1",
                public_key=pub_key1,
            )

            peer2 = manager.add_peer_to_config(
                config,
                allowed_ips=["10.0.0.3/32"],
                endpoint="192.0.2.2:51820",
                peer_name="client-2",
                public_key=pub_key2,
            )

            # 3. Validate configuration
            assert manager.validate_config(config)

            # 4. Save to file
            conf_path = tmp_path / "vpn-server.conf"
            manager.save_config(config, conf_path)

            # 5. Load from file
            loaded = manager.load_config(conf_path)

            # 6. Verify loaded configuration
            assert loaded.interface.address == ["10.0.0.1/24"]
            assert loaded.interface.listen_port == 51820
            assert len(loaded.peers) == 2

            # 7. Modify and save again (generate unique key for peer3)
        with habbing.openHab(name="peer3", temp=True) as (hby3, hab3):
            keygen3 = KERIKeyGenerator(hab=hab3)
            _, pub_key3, _ = keygen3.generate_keypair()

        with habbing.openHab(name="keriguard", temp=True) as (hby, hab):
            manager = WireguardConfigManager(hab=hab)
            loaded = manager.load_config(conf_path)

            manager.add_peer_to_config(
                loaded,
                allowed_ips=["10.0.0.4/32"],
                peer_name="client-3",
                public_key=pub_key3,
            )

            manager.save_config(loaded, conf_path, backup=True)

            # 8. Verify backup was created
            backup_path = conf_path.with_suffix(".conf.bak")
            assert backup_path.exists()

            # 9. Load final version
            final = manager.load_config(conf_path)
            assert len(final.peers) == 3

            # 10. Remove a peer
            result = manager.remove_peer_from_config(final, peer2.public_key)
            assert result is True
            assert len(final.peers) == 2

            # 11. Final validation
            assert manager.validate_config(final)
