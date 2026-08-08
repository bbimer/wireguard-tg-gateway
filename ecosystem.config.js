module.exports = {
  apps: [
    {
      name: "netsentinel-vpnbot",
      script: "vpn_bot.py",
      interpreter: "python3",
      autorestart: true,
      watch: false,
      max_memory_restart: "200M",
      env: {
        NODE_ENV: "production"
      }
    }
  ]
};
