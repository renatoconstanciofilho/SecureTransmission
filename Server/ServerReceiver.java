import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.SecretKeySpec;

/**
 * Criar novas chaves
 * Em modo administrador
 * openssl genrsa -out private.pem 2048
 * openssl pkcs8 -topk8 -in private.pem -outform DER -out private.der -nocrypt
 * openssl rsa -in private.pem -pubout -outform DER -out public.der
 * 
 * executar o servidor no diretorio: javac *.java | java ServerReceiver 
 */

public class ServerReceiver {
	private static final int PORT = 6666;

//	Carrega e fica aguardando
	public static void main(String[] args) throws Exception {
		System.out.println("Servidor aguardando...");
		ServerSocket listener = new ServerSocket(PORT);
		try {
			while (true) {
				new Handler(listener.accept()).start();
			}
		} finally {
			listener.close();
		}
	}

	private static class Handler extends Thread {
		private Socket socket;
		private InputStream entrada;
		private OutputStream saida;

		private void sendPublicKey() throws IOException {
//			Cria string com a chave pública, marcando no cabecalho
			StringBuilder messageHeader = new StringBuilder();
			messageHeader.append("CHAVE PUBLICA\n");
			File publicKeyFile = new File("public.der");
			messageHeader.append(publicKeyFile.length() + "\n\n");
			saida.write(messageHeader.toString().getBytes("ASCII"));
			saida.write(Files.readAllBytes(publicKeyFile.toPath()));
			saida.flush();
		}

		private void enviarMensagemErro(String msg) {
			try {
				msg = "ERROR\n" + msg + "\n\n";
				saida.write(msg.getBytes("ASCII"));
			} catch (IOException e) {
				System.out.println("Falha ao enviar mensagem de erro ao cliente.");
				System.exit(1);
			}
		}

		private byte[] decriptaAES(byte[] arquivoPK) throws GeneralSecurityException, IOException {
//			recebe a chave de criptografia AES
			byte[] chaveAESencriptada = new byte[ProtocolUtilities.KEY_SIZE_AES * 2];
			entrada.read(chaveAESencriptada);
			// Coloca a chave publica na devida estrutura
			PKCS8EncodedKeySpec chavePrivadaSpec = new PKCS8EncodedKeySpec(arquivoPK);
			PrivateKey chavePrivada = KeyFactory.getInstance("RSA").generatePrivate(chavePrivadaSpec);
			// Decripta a chave AES usando a chave privada RSA
			Cipher encriptadorChavePrivada = Cipher.getInstance("RSA");
			encriptadorChavePrivada.init(Cipher.DECRYPT_MODE, chavePrivada);
			CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(chaveAESencriptada), encriptadorChavePrivada);
			byte[] chaveAES = new byte[ProtocolUtilities.KEY_SIZE_AES / 8];
			cipherInputStream.read(chaveAES);
			cipherInputStream.close();
			return chaveAES;
		}
		
		private String scanLineFromCipherStream(CipherInputStream cstream) throws IOException {
			StringBuilder linha = new StringBuilder();
			char c;
			while ((c = (char) cstream.read()) != '\n') {
				linha.append(c);
			}
			return linha.toString();
		}
		
		private File receberArquivo(byte[] chaveAES) throws GeneralSecurityException, IOException {
			Cipher encriptadorAES = Cipher.getInstance("AES");
			SecretKeySpec chaveAESSpec = new SecretKeySpec(chaveAES, "AES");
			encriptadorAES.init(Cipher.DECRYPT_MODE, chaveAESSpec);
			CipherInputStream cipherInputStream = new CipherInputStream(entrada, encriptadorAES);
			String nomeDoArquivo = scanLineFromCipherStream(cipherInputStream);
			String tamanhoDoArquivo = scanLineFromCipherStream(cipherInputStream);
			File arquivoRecebido = new File(nomeDoArquivo.toString());
			FileOutputStream fos = new FileOutputStream(arquivoRecebido);
			ProtocolUtilities.sendBytes(cipherInputStream, fos, Long.parseLong(tamanhoDoArquivo));
			fos.flush();
			fos.close();
			return arquivoRecebido;
		}

		public Handler(Socket socket) {
			this.socket = socket;
		}

		public void run() {
			String comando;
			try {
				entrada = new BufferedInputStream(socket.getInputStream());
				saida = new BufferedOutputStream(socket.getOutputStream());
				ArrayList<String> partesCabecalho = ProtocolUtilities.quebraCabecalho(entrada);
				comando = partesCabecalho.get(0);
			} catch (IOException e) {
				e.printStackTrace();
				System.err.println("Conexão com o cliente caiu!");
				return;
			} catch (NullPointerException e) {
				System.err.println("Erro ao ler o comando do cliente.");
				return;
			}
			switch (comando) {
			case "SOLICITAR CHAVE PUBLICA":
				try {
					sendPublicKey();
					System.out.println("Chave pública enviada");
				} catch (IOException e) {
					System.err.println("Conexão com o cliente caiu. Não foi possível enviar a chave pública.");
				}
				break;
			case "ENVIO DE ARQUIVO":
				byte[] privateRsaKey;
				try {
					privateRsaKey = Files.readAllBytes(new File("private.der").toPath());
				} catch (IOException e) {
					enviarMensagemErro("SERVER ERROR");
					System.err.println("O servidor não conseguiu abir o arquivo com a chave privada.");
					return;
				}
				try {
					byte[] aesKey = decriptaAES(privateRsaKey);
					File file = receberArquivo(aesKey);
					System.out.println("Arquivo Recebido!");
					System.out.println("Nome: " + file.getName());
					System.out.println("Tamanho:" + file.length() + "bytes");
					saida.write("SUCESSO\ntransmissão feita com sucesso\n\n".getBytes("ASCII"));
					saida.flush();
					socket.close();
				} catch (GeneralSecurityException e) {
					enviarMensagemErro("Falha ao decriptar a chave AES e/ou o conteudo do arquivo.");
					System.err.println("O servidor falhou ao decriptar a chave AES e/ou o conteudo do arquivo.");
					return;
				} catch (IOException e) {
					e.printStackTrace();
					System.err.println("Conexão com o cliente caiu.");
					return;
				}
				break;
			default:
				enviarMensagemErro("COMANDO INVÁLIDO");
				System.out.println("Comando inválido detectados: " + comando);
			}
		}
	}
}