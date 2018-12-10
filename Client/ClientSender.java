import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class ClientSender {

	private static String hostName;
	private static int numeroPorta;

	private static boolean enviarArquivo(byte[] chavePublica, byte[] chaveAES, File arquivo)
			throws FileNotFoundException, IOException, GeneralSecurityException {
		Socket socket = new Socket(hostName, numeroPorta);
		BufferedOutputStream saida = new BufferedOutputStream(socket.getOutputStream());
		BufferedInputStream entrada = new BufferedInputStream(socket.getInputStream());
		// Enviar o cabeçalho e a chave AES encriptada com a chave pública.
		saida.write("ENVIO DE ARQUIVO\n\n".getBytes("ASCII"));
		enviaChaveAESCriptografada(saida, chavePublica, chaveAES);
		// Encriptado e enviado o nome do arquivo e o tamanho com AES
		String nomeDoArquivoETamanho = new String(arquivo.getName() + "\n" + arquivo.length() + "\n");
		ByteArrayInputStream informacoesDoArquivo = new ByteArrayInputStream(nomeDoArquivoETamanho.getBytes("ASCII"));
		SecretKeySpec especificacoesAES = new SecretKeySpec(chaveAES, "AES");
		Cipher ecriptadorAES = Cipher.getInstance("AES");
		ecriptadorAES.init(Cipher.ENCRYPT_MODE, especificacoesAES);
		CipherOutputStream cipherOutStream = new CipherOutputStream(saida, ecriptadorAES);
		ProtocolUtilities.sendBytes(informacoesDoArquivo, cipherOutStream);
//		Enviar o arquivo e alguns bytes para o encriptador identificar o fim do arquivo
		FileInputStream fileStream = new FileInputStream(arquivo);
		ProtocolUtilities.sendBytes(fileStream, cipherOutStream);
		saida.write(ecriptadorAES.doFinal());
		saida.write("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n".getBytes("ASCII"));
		saida.flush();
		ArrayList<String> serverResponse = ProtocolUtilities.quebraCabecalho(entrada);
		socket.close();
		if (!serverResponse.get(0).equals("SUCESSO")) {
			System.err.println("Erro ao enviar o aqrquivo. Mensagem do servidor:");
			for (String msg : serverResponse)
				System.err.println(msg);
			return false;
		}
		return true;
	}

	private static void enviaChaveAESCriptografada(OutputStream out, byte[] chavePublica, byte[] chaveAES)
			throws GeneralSecurityException, IOException {
		// Pega a chave publica e encripta a chave AES
		Cipher criptografaPK = Cipher.getInstance("RSA");
		PublicKey pk = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(chavePublica));
		criptografaPK.init(Cipher.ENCRYPT_MODE, pk);
		ByteArrayOutputStream tempByteStream = new ByteArrayOutputStream();
		CipherOutputStream streamCriptografia = new CipherOutputStream(tempByteStream, criptografaPK);
		streamCriptografia.write(chaveAES);
		streamCriptografia.close();
		tempByteStream.writeTo(out);
	}
	
	private static byte[] pegaChavePublica() throws IOException {
		// Conecta no endereço e porta
		Socket socket = new Socket(hostName, numeroPorta);
		BufferedOutputStream saida = new BufferedOutputStream(socket.getOutputStream());
		BufferedInputStream entrada = new BufferedInputStream(socket.getInputStream());
		// Enviar mensagem solicitando chave publica
		saida.write("SOLICITAR CHAVE PUBLICA\n\n".getBytes("ASCII"));
		saida.flush();
		ArrayList<String> cabecalho = ProtocolUtilities.quebraCabecalho(entrada);
		// Verifica se o cabeçalho está com a palavra CHAVE PUBLICA.
		if (!cabecalho.get(0).equals("CHAVE PUBLICA")) {
			System.err.println("Falha ao obter a chave pública. Mensagem do servidor:");
			for (String msg : cabecalho)
				System.err.println(msg);
			System.exit(1);
		}
		int tamanhoDaChave = Integer.parseInt(cabecalho.get(1));
		byte[] chavePublica = new byte[tamanhoDaChave];
		entrada.read(chavePublica);
		socket.close();
		return chavePublica;
	}

	private static byte[] gerarChaveAES() throws NoSuchAlgorithmException {
		byte[] chaveAES = null;
		KeyGenerator gerarChave = KeyGenerator.getInstance("AES");
		gerarChave.init(ProtocolUtilities.KEY_SIZE_AES); // Busca nas configurações o tamanho da chave AES (128bits)
		chaveAES = gerarChave.generateKey().getEncoded();
		return chaveAES;
	}

	public static void main(String[] args) {
		hostName = "localhost";
		numeroPorta = 6666;
		// Tentativa de configurar por linha de comando
		// try {
		// if (args.length == 2) {
		// hostName = args[0];
		// portNumber = Integer.parseInt(args[1]);
		// } else if (args.length == 0)
		// ; // use defaults if no host name and port number are provided.
		// else
		// throw new IllegalArgumentException();
		// } catch (IllegalArgumentException e) {
		// System.out.println("Usage: java ClientSender [hostName portNumber]");
		// System.exit(1);
		// }
		System.out.println("Conectando ao servidor: " + hostName + " porta: " + numeroPorta + "...");
		byte[] chavePublicaRSA, chaveAES;
		File[] arquivosDoDiretorio = new File(Paths.get(".").toAbsolutePath().toString()).listFiles();
		System.out.println("Arquivos disponíveis no diretorio:");
		for (File f : arquivosDoDiretorio) {
			String nomeDoArquivo = f.getName();
			if (nomeDoArquivo.charAt(0) == '.') // Ignorar arquivos ocultos.
				continue;
			System.out.println(nomeDoArquivo);
		}
		try {
			chavePublicaRSA = pegaChavePublica();
			chaveAES = gerarChaveAES();
			Scanner scanner = new Scanner(System.in);
			System.out.println("Qual arquivo deseja enviar: ");
			String nomeDoArquivo = scanner.next();
			boolean sucesso = enviarArquivo(chavePublicaRSA, chaveAES, new File(nomeDoArquivo));
			if (sucesso) {
				System.out.println("Arquivo enviado com sucesso!");
			} else {
				System.out.println("Arquivo não enviado!");
			}
			scanner.close();
		} catch (FileNotFoundException e) {
			System.err.println("Arquivo não encontrado.");
		} catch (IOException e) {
			System.err.println("Erro ao conectar no servidor.");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Falha ao gerar chave AES.");
		} catch (GeneralSecurityException e) {
			System.err.println("Erro de segurança desconhecido.");
		}
	}
}