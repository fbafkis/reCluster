import { injectable } from 'tsyringe';
import axios from 'axios';
import { logger } from '~/logger';
import { PowerOnDeviceError } from '~/errors';

@injectable()
export class SmartPlugService {
  // Function to get the power state of the smart plug
  private async getPowerState(address: string, nodeId: string): Promise<boolean> {
    const url = `http://${address}/cm?cmnd=Power`;
    try {
      const response = await axios.get(url);
      const powerState = response.data.POWER;
      return powerState === 'ON';
    } catch (error: unknown) {
      if (axios.isAxiosError(error)) {
        // Axios-specific error
        logger.error(`Error getting power state from power on smart plug at ${address} for the node ${nodeId}: ${error.message}`);
      } else if (error instanceof Error) {
        // General error
        logger.error(`Error getting power state from power on smart plug at ${address} for the node ${nodeId}: ${error.message}`);
      } else {
        // Unknown error type
        logger.error(`Error getting power state from power on smart plug at ${address} for the node ${nodeId}: ${error}`);
      }
      throw new PowerOnDeviceError(`Could not get power state from power on smart plug at ${address} for the node ${nodeId}`);
    }
  }

  // Function to set the power state of the Smart Plug
  private async setPowerState(address: string, nodeId: string, state: 'ON' | 'OFF'): Promise<void> {
    const url = `http://${address}/cm?cmnd=Power%20${state}`;
    try {
      await axios.get(url);
    } catch (error: unknown) {
      if (axios.isAxiosError(error)) {
        // Axios-specific error
        logger.error(`Error setting power state on power on smart plug at ${address} for the node ${nodeId}: ${error.message}`);
      } else if (error instanceof Error) {
        // General error
        logger.error(`Error setting power state on power on smart plug at ${address} for the node ${nodeId}: ${error.message}`);
      } else {
        // Unknown error type
        logger.error(`Error setting power state on power on smart plug at ${address} for the node ${nodeId}: ${error}`);
      }
      throw new PowerOnDeviceError(`Could not set power state on power on smart plug at ${address} for the node ${nodeId}`);
    }
  }


  // Function to toggle the power state of the Smart Plug
  private async togglePowerState(address: string, nodeId:string): Promise<void> {
    const currentState = await this.getPowerState(address, nodeId);
    if (currentState) {
      // If currently on, turn off and then turn on again
      await this.setPowerState(address, nodeId, 'OFF');
      await new Promise((resolve) => setTimeout(resolve, 2000)); // Wait for 2 seconds
    }
    // Turn on
    await this.setPowerState(address, nodeId, 'ON');
  }

  // Public function to handle the power on logic
  public async powerOn(address: string, nodeId: string): Promise<void> {
    logger.info(`Powering on power on smart plug at ${address} for the node ${nodeId}`);
    await this.togglePowerState(address, nodeId);
    logger.info(`Power on smart plug at ${address} for the node ${nodeId} powered on successfully`);
  }
}
