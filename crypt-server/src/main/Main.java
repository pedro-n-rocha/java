package main; 

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.util.internal.logging.InternalLoggerFactory;
import io.netty.util.internal.logging.JdkLoggerFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.operator.OperatorCreationException;

public class Main 
{
	private final static Logger log = Logger.getLogger(Main.class.getName());
	
	String stype = "JKS";	
	private SSLContext sslctx;
	KeyPairGenerator kpg = null ; 

	public static void main(String[] args) 
	{
		InternalLoggerFactory.setDefaultFactory(new JdkLoggerFactory());
		
		log.info("|_starting_|...................|\n\n");
		try 
		{
			new Main().init();
		} catch (Exception ex) 
		{
			log.warning(ex.getMessage());
		}
		log.info("\n\n|.....................|_stoped_|");
	}

	public void init() throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException, UnrecoverableKeyException, KeyManagementException, OperatorCreationException, InterruptedException 
	{
		kpg = KeyPairGenerator.getInstance("RSA"); 
		
		String ksfile = "keystore";
		String kspwd = "123qwe";

		String tsfile = "truststore";
		String tspwd = "123qwe";

		KeyStore ks = initStore(ksfile, kspwd);
		KeyStore ts = initStore(tsfile, tspwd);
	
		final X509KeyManager finalKm = initKm(ks , kspwd);
		final X509TrustManager ftm = initTm(ts);
		DelegateTrustManager dtm = new DelegateTrustManager(ftm);
		
		sslctx = SSLContext.getInstance("TLS");
		sslctx.init(new KeyManager[] { finalKm }, new TrustManager[] { dtm }, null);
					
		for(int i = 0 ; i < 2 ; i++  ){
			addRandCert(ts);
		}

		dtm.reloadMem(ts);		
		dtm.saveStore(ts, tsfile, tspwd);
			
		// Configure the server.
        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        try {            
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
             .channel(NioServerSocketChannel.class)
            // .handler(new LoggingHandler(LogLevel.INFO))
             .childHandler(new SslServerInitializer(sslctx));
            b.bind(1234).sync().channel().closeFuture().sync();
            
        } finally {
            // Shut down all event loops to terminate all threads.
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
	}
	
	
	private void addRandCert(KeyStore ks ) throws KeyStoreException, OperatorCreationException, IOException{
		addCert(ks, String.valueOf(System.currentTimeMillis()), genRandCert()); 
	}
	
	private Certificate genRandCert() throws OperatorCreationException, IOException{
		KeyPair kp = kpg.generateKeyPair();
		return SelfSignedCertificateGenerator.getCerts(kp) ; 
	}
	
	private void addCert(KeyStore ks ,  String alias  , Certificate cert ) throws KeyStoreException, OperatorCreationException, IOException{	
		ks.setCertificateEntry(alias , cert);
	}

	private X509KeyManager initKm(KeyStore ks , String kspwd) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException
	{	
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
				.getDefaultAlgorithm());
		kmf.init(ks, kspwd.toCharArray());

		X509KeyManager x509Km = null;
		for (KeyManager km : kmf.getKeyManagers()) {
			if (km instanceof X509KeyManager) {
				x509Km = (X509KeyManager) km;
				break;
			}
		}
		return x509Km ; 
	}
	
	
	private X509TrustManager initTm(KeyStore ts) throws NoSuchAlgorithmException, KeyStoreException
	{	
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory
				.getDefaultAlgorithm());
		tmf.init(ts);
		
		X509TrustManager x509Tm = null;
		for (TrustManager tm : tmf.getTrustManagers()) {
			if (tm instanceof X509TrustManager) {
				x509Tm = (X509TrustManager) tm;
				break;
			}
		}
		return x509Tm ; 
	}
	
	private KeyStore initStore(String file, String pwd) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException 
	{
		KeyStore s = KeyStore.getInstance(stype);
		InputStream is = new FileInputStream(file);
		s.load(is, pwd.toCharArray());
		is.close();
		return s;
	}
	
	class DelegateTrustManager implements X509TrustManager 
	{
		X509TrustManager tm;

		DelegateTrustManager(final X509TrustManager _tm) {
			tm = _tm;
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() 
		{
			log.info("getAcceptedIssuers");
			X509Certificate[] issuers = tm.getAcceptedIssuers();
			//return new  X509Certificate[0]; // bug: store muito cheia 
			return issuers ;
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType)
				throws CertificateException 
		{
			log.info("checkServerTrusted");
			tm.checkServerTrusted(chain, authType);
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType)
				throws CertificateException 
		{
			log.info("checkClientTrusted");
			try{
				tm.checkClientTrusted(chain, authType);
			}catch(CertificateException cx){
				log.warning(cx.getCause().toString() ) ; 
				throw cx ; 
			}
		}

		public void reloadMem(KeyStore ts) throws KeyStoreException,
				NoSuchAlgorithmException, CertificateException, IOException {	
			tm = initTm(ts); 
		}
		
		public void saveStore(KeyStore ts , String file , String pwd) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
			FileOutputStream fos = new FileOutputStream(file);
			ts.store(fos,pwd.toCharArray());
			fos.close();
			
		}

	}
}
