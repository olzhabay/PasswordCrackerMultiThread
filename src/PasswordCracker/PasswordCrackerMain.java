package PasswordCracker;

import java.lang.String;
import java.util.concurrent.*;

public class PasswordCrackerMain {
    public static void main(String args[]) {
        if (args.length < 4) {
            System.out.println("Usage: PasswordCrackerMain numThreads passwordLength isEarlyTermination encryptedPassword");
            return;
        }
        
        int numThreads = Integer.parseInt(args[0]);
        int passwordLength = Integer.parseInt(args[1]);
        boolean isEarlyTermination = Boolean.parseBoolean(args[2]);
        String encryptedPassword = args[3];
        
        // If you want to know the ExecutorService,
        // refer to site; https://docs.oracle.com/javase/8/docs/api/java/util/concurrent/ExecutorService.html
        ExecutorService  workerPool = Executors.newFixedThreadPool(numThreads);
        PasswordFuture passwordFuture = new PasswordFuture();
        PasswordCrackerConsts consts = new PasswordCrackerConsts(numThreads, passwordLength, encryptedPassword);

		/*
         * Create PasswordCrackerTask and use executor service to run in a separate thread
		*/
        for (int i = 0; i < numThreads; i++) {
            /** COMPLETE **/
            workerPool.execute(new PasswordCrackerTask(i, isEarlyTermination, consts, passwordFuture));
        }
        System.out.println("20175324");
        System.out.println(numThreads);
        System.out.println(passwordLength);
        System.out.println(isEarlyTermination);
        System.out.println(encryptedPassword);
        try {
            System.out.println(passwordFuture.get());
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            workerPool.shutdown();
        }
    }
}


