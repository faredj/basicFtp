package zSecuriteProject;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;
import org.bouncycastle.jce.PKCS10CertificationRequest;

@SuppressWarnings("deprecation")
public class Client implements Runnable{
	Charset c = Charset.forName("UTF-8");
	private String name;
	private SocketChannel sc;
	private String host;
	final private int caPort = 3344;
	final String clientPsw = "clientPassword";
	private X509Certificate clientCertificate;
	private X509Certificate caCertificate;
	private KeyPair clientKp;
	private KeyStore clientKs;
	public Client(String name, String host) {
		try {
			sc = SocketChannel.open();
		} catch (IOException e) {
			e.printStackTrace();
		}
		this.name = name;
		this.host = host;
	}
	
	public String getName() {
		return name;
	}
	
	public void setName(String name) {
		this.name = name;
	}
	
	public SocketChannel getSc() {
		return sc;
	}

	public void setSc(SocketChannel sc) {
		this.sc = sc;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public String getClientPsw() {
		return clientPsw;
	}

	public int getCaPort() {
		return caPort;
	}

	public X509Certificate getClientCertificate() {
		return clientCertificate;
	}

	public void setClientCertificate(X509Certificate clientCertificate) {
		this.clientCertificate = clientCertificate;
	}

	public X509Certificate getCaCertificate() {
		return caCertificate;
	}

	public void setCaCertificate(X509Certificate caCertificate) {
		this.caCertificate = caCertificate;
	}

	public KeyPair getClientKp() {
		return clientKp;
	}

	public void setClientKp(KeyPair clientKp) {
		this.clientKp = clientKp;
	}

	public KeyStore getClientKs() {
		return clientKs;
	}

	public void setClientKs(KeyStore clientKs) {
		this.clientKs = clientKs;
	}

	public KeyPair generateKeyPair(){//génération d'une paire de clés
		KeyPair kp = null;
		KeyPairGenerator kgp;
		try {
			kgp = KeyPairGenerator.getInstance("RSA");
			kgp.initialize(1024);
			kp = kgp.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return kp;
	}
	
	public PKCS10CertificationRequest generateCSR(KeyPair kp){//génération d'un csr
		X500Principal subject = new X500Principal ("CN="+this.getName());
		PKCS10CertificationRequest pkcs = null;
			try {
				pkcs = new PKCS10CertificationRequest("SHA1withRSA", subject, kp.getPublic(), null, kp.getPrivate());
			} catch (InvalidKeyException e) {
				System.out.println(e.getMessage());
			} catch (NoSuchAlgorithmException e) {
				System.out.println(e.getMessage());
			} catch (NoSuchProviderException e) {
				System.out.println(e.getMessage());
			} catch (SignatureException e) {
				System.out.println(e.getMessage());
			}
		return pkcs;
	}
	public ByteBuffer askCaForCertificate(){
		InetSocketAddress adrSc = new InetSocketAddress(this.getHost(), this.getCaPort());
		SocketChannel sc = this.getSc();
		ByteBuffer bb = ByteBuffer.allocate(2048);
		bb.clear();
		try {
			sc.connect(adrSc);
			sc.configureBlocking(false);
			bb.put((byte) 1);
			int strSize = this.getName().length();
			bb.putInt(strSize);
			ByteBuffer nameByte = c.encode(this.getName());
			bb.put(nameByte);
			bb.flip();
			while(bb.hasRemaining()){
				System.out.println(sc.write(bb));
				System.out.println(bb);
			}
			bb.clear();
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			while(sc.read(bb) > 0);
			System.out.println("byte lu : "+bb);
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}
		return bb;
	}
	
	public KeyStore generateNewKeyStore() throws Exception{
		KeyStore ks = null;
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(null, this.getClientPsw().toCharArray());
			ks.setCertificateEntry(this.getName(), this.getClientCertificate());
			ks.setCertificateEntry(this.getCaCertificate().getSubjectDN().getName(), this.getCaCertificate());
			ks.setKeyEntry("caPrivateKey", this.getClientKp().getPrivate(), this.getClientPsw().toCharArray(), new java.security.cert.Certificate[]{this.getClientCertificate()});
			FileOutputStream caKeyStore = new FileOutputStream(this.getName()+"/caKeyStore.store");
			ks.store(caKeyStore, this.getClientPsw().toCharArray());
			caKeyStore.close();
		return ks;
	}
	
	@Override
	public void run() {
		if(!(new File(this.getName()).exists())){//si le client ne posséde pas de repertoire on va le créer
			new File(this.getName()).mkdir();
			
			//generate key pair
			this.setClientKp(this.generateKeyPair());
			
			//generate csr (PKCS)
			PKCS10CertificationRequest csr = this.generateCSR(this.getClientKp());
			FileOutputStream csrOutput;
			try {
				csrOutput = new FileOutputStream(this.getName()+"/myCsr.req");
				csrOutput.write(csr.getEncoded());
				csrOutput.close();
				ByteBuffer bb = this.askCaForCertificate();
				bb.flip();
				System.out.println("vvvv"+bb);
				int ccSize = bb.getInt();
				System.out.println("111"+ccSize);
				byte[] clientCertByte = new byte[ccSize];
				bb.get(clientCertByte);
				
				int cacSize = bb.getInt();
				System.out.println("222"+cacSize);
				byte[] caCertByte = new byte[cacSize];
				bb.get(caCertByte);
				
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				InputStream in = new ByteArrayInputStream(clientCertByte);
				X509Certificate clientCert = (X509Certificate) cf.generateCertificate(in);
				this.setClientCertificate(clientCert);
				System.out.println(this.getClientCertificate());
				
				in = new ByteArrayInputStream(caCertByte);
				X509Certificate caCert = (X509Certificate) cf.generateCertificate(in);
				this.setCaCertificate(caCert);
				System.out.println(this.getCaCertificate());
				
				this.setClientKs(this.generateNewKeyStore());
			} catch (Exception e) {
				System.out.println(e.getMessage());
			} 
		}else{//sinon on charge le keystore
			
		}
	}
	
	public static void main(String[] args) throws IOException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Client c = new Client("faredjDirectory", "localhost");
		Thread t1 = new Thread(c);
		t1.start();
	}

}
