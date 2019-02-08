package zSecuriteProject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class CertificationAutority implements Runnable{
	final public int portCa = 3344;
	Charset c = Charset.forName("UTF-8");
	Selector selector= null;
	ServerSocketChannel server = null;
	SocketChannel sc;
	final String caName = "CA";
	final String caPsw = "caPassword";
	private KeyPair caKeyPair;
	private KeyStore caKeyStore;
	private X509Certificate caCertificate;
	private ByteBuffer bBuffer=ByteBuffer.allocate(2048);
	public CertificationAutority() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		this.initCA();
		try {
			server = ServerSocketChannel.open();
			server.configureBlocking(false);
			InetSocketAddress adr = new InetSocketAddress(portCa);
			server.socket().bind(adr);
			selector = Selector.open();
			server.register(selector, SelectionKey.OP_ACCEPT);
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}
	}
	
	public String getCaName() {
		return caName;
	}

	public String getCaPsw() {
		return caPsw;
	}

	public KeyPair getCaKeyPair() {
		return caKeyPair;
	}

	public void setCaKeyPair(KeyPair caKeyPair) {
		this.caKeyPair = caKeyPair;
	}

	public KeyStore getCaKeyStore() {
		return caKeyStore;
	}

	public X509Certificate getCaCertificate() {
		return caCertificate;
	}

	public void setCaCertificate(X509Certificate caCertificate) {
		this.caCertificate = caCertificate;
	}

	public void setCaKeyStore(KeyStore caKeyStore) {
		this.caKeyStore = caKeyStore;
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
	@SuppressWarnings("deprecation")
	public X509Certificate generateAutoSignedCertificate(){
		this.setCaKeyPair(this.generateKeyPair());
		Date date = new Date();
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setPublicKey(this.getCaKeyPair().getPublic());
		certGen.setIssuerDN(new X500Principal("CN="+this.getCaName()+"[AUTORITE]"));
		certGen.setSubjectDN(new X500Principal("CN="+this.getCaName()));
		certGen.setNotBefore(date); 
		date.setMonth(date.getMonth()+10);
		certGen.setNotAfter(date);
		certGen.setSignatureAlgorithm("SHA1withRSA");
		
		X509Certificate certificate = null;
		try {
			certificate = certGen.generateX509Certificate(this.getCaKeyPair().getPrivate());
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return certificate;
	}
	public KeyStore generateNewKeyStore() throws Exception{
		KeyStore ks = null;
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(null, caPsw.toCharArray());
			this.setCaCertificate(this.generateAutoSignedCertificate());
			ks.setCertificateEntry(this.getCaName(), this.getCaCertificate());
			ks.setKeyEntry("caPrivateKey", this.getCaKeyPair().getPrivate(), this.getCaPsw().toCharArray(), new java.security.cert.Certificate[]{this.getCaCertificate()});
			FileOutputStream caKeyStore = new FileOutputStream(this.getCaName()+"/caKeyStore.store");
			ks.store(caKeyStore, this.getCaPsw().toCharArray());
			caKeyStore.close();
		return ks;
	}
	
	public void initCA() {
		if(!(new File(this.getCaName()).exists())){//initialisation du repertoire du CA
			new File(this.getCaName()).mkdir();
			try {
				this.setCaKeyStore(this.generateNewKeyStore());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}else{//sinon on charge le keystore
			KeyStore ks;
			try {
				FileInputStream fis = new FileInputStream(this.getCaName()+"/caKeyStore.store");
				ks = KeyStore.getInstance(KeyStore.getDefaultType());
				ks.load(fis, this.getCaPsw().toCharArray());
				fis.close();
				this.setCaKeyStore(ks);
			} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	@SuppressWarnings("deprecation")
	public X509Certificate generateCertificate(String nomClient) throws Exception{
		X509Certificate clientCert = null;
		try {
			@SuppressWarnings("resource")
//			PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(nomClient+"/myCsr.req")));
//			PemObject pem = pemReader.readPemObject();
//			PKCS10CertificationRequest csr = new PKCS10CertificationRequest(pem.getContent());
			FileInputStream fis = new FileInputStream(nomClient+"/myCsr.req");
			byte[] bb = new byte[fis.available()];
			fis.read(bb);
			fis.close();
			PKCS10CertificationRequest csr = new PKCS10CertificationRequest(bb);
			
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			Date date = new Date();
			certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
			certGen.setIssuerDN(new X500Principal("CN="+this.getCaName()+"[AUTORITE]"));
			certGen.setSubjectDN(new X500Principal(csr.getCertificationRequestInfo().getSubject().toString()));
			certGen.setNotBefore(date); 
			date.setMonth(date.getMonth()+10);
			certGen.setNotAfter(date);
			certGen.setPublicKey(csr.getPublicKey());
			certGen.setSignatureAlgorithm("SHA1withRSA");
			try {
				clientCert = certGen.generateX509Certificate(this.getCaKeyPair().getPrivate());
			} catch (Exception e) {
				e.printStackTrace();
			}
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		return clientCert;
	}
	
	@Override
	public void run() {
		while (true) {
			try {
				selector.select();
				Iterator<SelectionKey> keyIt = selector.selectedKeys().iterator();
				while (keyIt.hasNext()) {
					SelectionKey key = keyIt.next();
					if(key.isAcceptable()){
						SocketChannel client = server.accept();
						if(client != null){
							client.configureBlocking(false);
							client.register(selector, SelectionKey.OP_READ);
							System.out.println("Nouveau client : "+client.getRemoteAddress());
						}
					}else if(key.isReadable()){
						SocketChannel channel = (SocketChannel) key.channel();
						ByteBuffer bb = ByteBuffer.allocate(80000);
						bb.clear();
						while(channel.read(bb) > 0){}
						bb.flip();
						System.out.println(bb.get());
						int strSize = bb.getInt();
						ByteBuffer name = ByteBuffer.allocate(strSize);
						int p = bb.position()+strSize;
						while(bb.position() != p){
							System.out.println("BB  "+bb);
							System.out.println("Na  "+name);
							name.put(bb.get());
						}
						name.flip();
						CharBuffer cb = c.decode(name);
						System.out.println(cb.toString());
						X509Certificate clientCert = null;
						bb.clear();
						try {
							clientCert = this.generateCertificate(cb.toString());
							int ccSize = clientCert.getEncoded().length;
							int cacSize = this.getCaCertificate().getEncoded().length;
							bb.putInt(ccSize);
							bb.put(clientCert.getEncoded());
							bb.putInt(cacSize);
							bb.put(this.getCaCertificate().getEncoded());
							bb.flip();
							System.out.println(bb);
							while(bb.hasRemaining()){
								System.out.println("envoi du ca > "+channel.write(bb));
							}
						} catch (Exception e) {
							e.printStackTrace();
						}
						channel.close();
					}
					keyIt.remove();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}
	public static void main(String[] args) {
		CertificationAutority ca = new CertificationAutority();
		Thread t = new Thread(ca);
		System.out.println("lancement CA...");
		t.start();
	}
}
