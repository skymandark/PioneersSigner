import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Test {

    public static void main(String[] args) {
         String content  =null;
        try {
             content = Files.readString(Paths.get("C:\\Users\\Ab.abdelsattar\\Downloads\\PioneersSigner\\PioneersSigner\\invoice.txt"));
            System.out.println(content); // entire file as one String
        } catch (IOException e) {
            e.printStackTrace();
        }
        CadesBesSigner cadesBesSigner = new CadesBesSigner();
        try {
        String s=      cadesBesSigner.startInvoiceSigning(content);
        } catch(Exception e)
        {

            e.printStackTrace();
        }


    }
}