"""Compatibility entry point for local preview and existing tests."""
from family_vpn.app import APNsSender, Settings, create_app, seed_demo

if __name__ == "__main__":
    from family_vpn.app import main
    main()
