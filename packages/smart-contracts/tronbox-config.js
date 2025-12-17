module.exports = {
  contracts_directory: 'src/contracts',
  contracts_build_directory: '../build/tronbox/contracts',
  networks: {
    mainnet: {
      privateKey: process.env.PK_MAINNET,
      userFeePercentage: 100,
      feeLimit: 1000 * 1e6,
      fullHost: 'https://api.trongrid.io',
      network_id: '1'
    },
    nile: {
      privateKey: process.env.PK_NILE,
      userFeePercentage: 100,
      feeLimit: 1000 * 1e6,
      fullHost: 'https://nile.trongrid.io',
      network_id: '3'
    },
    development: {
      mnemonic: 'spawn man lecture main execute duck prosper banana almost vehicle betray weasel',
      userFeePercentage: 0,
      feeLimit: 1000 * 1e6,
      fullHost: 'http://127.0.0.1:9090',
      network_id: '*'
    }
  },
  compilers: {
    solc: {
      version: '0.8.18',
      settings: {
        optimizer: {
          enabled: true,
          runs: 200
        },
        evmVersion: 'istanbul',
        viaIR: true,
      }
    }
  }
};
