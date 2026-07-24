const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ChronosStaking & Verifier", function () {
  let verifier, staking, owner, agent1, agent2;

  beforeEach(async function () {
    [owner, agent1, agent2] = await ethers.getSigners();

    // Deploy Verifier
    const Verifier = await ethers.getContractFactory("ChronosVerifier");
    verifier = await Verifier.deploy();

    // Deploy Staking
    const Staking = await ethers.getContractFactory("ChronosStaking");
    staking = await Staking.deploy(verifier.target);
  });

  it("Should allow an agent to register by staking 1 ETH", async function () {
    const stakeAmount = ethers.parseEther("1.0");
    await expect(staking.connect(agent1).registerAgent({ value: stakeAmount }))
      .to.emit(staking, "AgentRegistered")
      .withArgs(agent1.address);

    const agentData = await staking.agents(agent1.address);
    expect(agentData.isActive).to.be.true;
    expect(agentData.stake).to.equal(stakeAmount);
  });

  it("Should assign tasks to an active agent", async function () {
    const stakeAmount = ethers.parseEther("1.0");
    await staking.connect(agent1).registerAgent({ value: stakeAmount });

    await expect(staking.assignTask(agent1.address, 1001))
      .to.emit(staking, "TaskAssigned")
      .withArgs(agent1.address, 1001);

    const agentData = await staking.agents(agent1.address);
    expect(agentData.pendingTasks).to.equal(1);
  });

  it("Should successfully verify a ZK-SNARK proof and complete a task", async function () {
    const stakeAmount = ethers.parseEther("1.0");
    await staking.connect(agent1).registerAgent({ value: stakeAmount });
    await staking.assignTask(agent1.address, 1001);

    // Mock Groth16 proof arrays (A, B, C, Input)
    const a = [1, 2];
    const b = [[3, 4], [5, 6]];
    const c = [7, 8];
    const input = [9];

    await expect(staking.connect(agent1).submitErasureProof(1001, a, b, c, input))
      .to.emit(staking, "ProofSubmitted")
      .withArgs(agent1.address, 1001, true);

    const agentData = await staking.agents(agent1.address);
    expect(agentData.pendingTasks).to.equal(0);
  });

  it("Should fail and slash the agent if the ZK-SNARK proof is invalid (e.g. [0,0])", async function () {
    const stakeAmount = ethers.parseEther("1.0");
    await staking.connect(agent1).registerAgent({ value: stakeAmount });
    await staking.assignTask(agent1.address, 1002);

    // Invalid proof points (zeros trigger the revert in ChronosVerifier)
    const a = [0, 0];
    const b = [[0, 0], [0, 0]];
    const c = [0, 0];
    const input = [0];

    // The transaction should revert because of the `require` in ChronosVerifier
    await expect(
      staking.connect(agent1).submitErasureProof(1002, a, b, c, input)
    ).to.be.revertedWith("Invalid proof point A");
  });
});
