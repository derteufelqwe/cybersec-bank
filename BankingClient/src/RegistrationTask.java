import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.util.Scanner;

/**
 * Registers the current device on the server.
 */
public class RegistrationTask extends Task
{
    /**
     * A scanner object to read terminal input.
     */
    private final Scanner _terminalScanner;
    /**
     * The name of the user currently logged in.
     */
    private final String _userName;
    /**
     * Prefix for the device code file path.
     */
    private final String _deviceCodeFilePathPrefix;
    /**
     * Tells whether the transaction was successful.
     */
    private boolean _successful = false;

    private final KeyPair keyPair = DiffieHellman.generateKeyPair();

    /**
     * Creates a registration task.
     *
     * @param socketInputStream        The socket input stream.
     * @param socketOutputStream       The socket output stream.
     * @param terminalScanner          A scanner object to read terminal input.
     * @param userName                 The name of the user currently logged in.
     * @param deviceCodeFilePathPrefix Base path of the device code file (default is
     *                                 the working directory).
     */
    public RegistrationTask(DataInputStream socketInputStream, DataOutputStream socketOutputStream, Scanner terminalScanner, String userName, String deviceCodeFilePathPrefix)
    {
        // Call superclass constructor
        super(socketInputStream, socketOutputStream);

        // Save parameters
        _terminalScanner = terminalScanner;
        _userName = userName;
        _deviceCodeFilePathPrefix = deviceCodeFilePathPrefix;
    }

    /**
     * Executes the registration.
     */
    public void run() throws IOException
    {

        // Inform server about registration
        String prePacket = "registration";
        System.err.println("Sending registration header packet...");
        Utility.sendPacket(_socketOutputStream, prePacket);

        // Generate half of registration code
        System.err.println("Generating and sending registration code part 1/2...");
        String registrationCodePart1 = DiffieHellman.pubKeyToString(keyPair.getPublic());
        Utility.sendPacket(_socketOutputStream, registrationCodePart1);

        // Receive other half of registration code from server
        System.err.println("Waiting for registration code part 2/2...");
        String registrationCodePart2 = Utility.receivePacket(_socketInputStream);
        if (registrationCodePart2.length() != 50)
        {
            // Output response and stop registration process
            System.err.println("Received invalid registration code part from server: " + registrationCodePart2);
            return;
        }
        String registrationCode = DiffieHellman.doECDH(DiffieHellman.pubKeyFromString(registrationCodePart2), keyPair.getPrivate());
        System.err.println("Received full registration code.");
        String confirmationCode = registrationCode.substring(0, 4);
        Utility.sendPacket(_socketOutputStream, confirmationCode);

        // Wait for confirmation by server
        System.err.println("Waiting for server confirmation...");
        String serverConfirmation = Utility.receivePacket(_socketInputStream);
        System.err.println("Server response: " + serverConfirmation);
        if (!serverConfirmation.equals("Registration successful."))
            return;

        _successful = true;
    }

    /**
     * Returns whether the registration was successful.
     *
     * @return Whether the registration was successful.
     */
    public boolean getSuccessful()
    {
        return _successful;
    }
}