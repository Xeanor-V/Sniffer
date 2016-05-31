package util;

import java.io.File;
import java.io.IOException;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

public class FileChooser {

    private String fileName = "";
    private File fileSelected = null;

    public FileChooser() {
        JFileChooser fileChooser = new JFileChooser();
        FileNameExtensionFilter extension = new FileNameExtensionFilter("archivos pcap (*.pcap)", "pcap");
        fileChooser.setFileFilter(extension);
        fileChooser.setDialogTitle("Abrir archivo");
        // set selected filter
        fileChooser.setFileFilter(extension);
        int resultado = fileChooser.showOpenDialog(null);
        if (resultado == JFileChooser.APPROVE_OPTION) {
            File f = fileChooser.getSelectedFile();
            System.out.println("Archivo seleccionado: " + f.getAbsolutePath());
            fileSelected = f;
        }
    }

    public String getFileName() {
        return fileSelected.getName();
    }

    public File getFile() {
        return fileSelected;
    }

    public String getAbsolutePath() {
        return fileSelected.getAbsolutePath();
        
    }
    
    public String getCanonicalPath() throws IOException{
        return fileSelected.getCanonicalPath();
    }
    
    public String getPath(){
        return fileSelected.getPath();
    }
    
    public String getASCII(){
        return fileSelected.getAbsoluteFile().toURI().toASCIIString();
    }
}
