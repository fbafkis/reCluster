import { injectable } from 'tsyringe';
import axios from 'axios';
import { logger } from '~/logger';
import { PowerOnDeviceError } from '~/errors';

@injectable()
export class ButtonPressDeviceService {

  // Public function to handle the power on logic of the BPD
  public async pressButton(address: string, nodeId: string): Promise<void>  {
    //TODO: set the correct url for BPD API
    const url = `http://${address}/press`;
    logger.info(`Pressing button on button press device at ${address} for the node ${nodeId} successfully.`);
    try {
      const response = await axios.get(url);
      const pressingOutcome = response.data.outcome;
    if(pressingOutcome === "SUCCESS"){
      logger.info(`Button pressed succesfully by the button press device at ${address} for the node ${nodeId}.`);
        } else if (pressingOutcome === "FAILURE"){
          throw new PowerOnDeviceError (`The button press device at ${address} for the node ${nodeId} reported a failure while pressing the button.`);
        } else {
          throw new PowerOnDeviceError (`Unknown error for the button press device at ${address} for the node ${nodeId} while pressing the button.`);
        }

    } catch (error: unknown) {
      if (axios.isAxiosError(error)) {
        // Axios-specific error
        logger.error(`Netwrok error setting power state on power on smart plug at ${address} for the node ${nodeId}: ${error.message}.`);
      } else if (error instanceof Error) {
        // Unkwnown errror
        logger.error(`Unknown error setting power state on power on smart plug at ${address} for the node ${nodeId}: ${error.message}.`);
      }
      throw new PowerOnDeviceError(`Could not set power state on power on smart plug at ${address} for the node ${nodeId}. It was not possible to reach the button press device.`);
    }
  }
}
