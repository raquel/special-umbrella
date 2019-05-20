package com.example.artifact;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Scanner;


@SpringBootApplication
public class ArtifactApplication implements CommandLineRunner {

    private static Log log = LogFactory.getLog(ArtifactApplication.class);

    public static void main(String[] args) {
        log.info("Começando os trabalhos");
        SpringApplication.run(ArtifactApplication.class, args);
        log.info("Terminando os trabalhos");
    }

    @Override
    public void run(String... args) {
        CognitoHelper helper = new CognitoHelper();

        System.out.println("Здравствуйте. Добро пожаловать на консоль. Выберите один из вариантов:.\n" +
                "1. Criar usuario\n" +
                "2. Autenticar usuario\n" +
                "3. Resetar Senha - Não Implementado\n" +
                "4. Deletar usuario - Não Implementado\n" +
                "");
        int choice = 0;
        Scanner scanner = new Scanner(System.in);
        try {
            choice = Integer.parseInt(scanner.nextLine());
        } catch (NumberFormatException exp) {
            System.out.println("Escolha uma opção:");
            System.exit(1);
        }
        switch (choice) {
            case 1:
                createUser(helper);
                break;
            case 2:
                validateUser(helper);
                break;
//            case 3:
//                resetPassword(helper);
//                break;
//            case 4:
//                deleteUser(helper);
//                break;
            default:
                System.out.println("Errô, digita de novo!");
        }
    }

    private static void createUser(CognitoHelper helper) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Username: ");
        String username = scanner.nextLine();

        System.out.println("Password: ");
        String password = scanner.nextLine();

        System.out.println("Email: ");
        String email = scanner.nextLine();

        System.out.println("Telefone (+11234567890): ");
        String phonenumber = scanner.nextLine();

        boolean success = helper.signUpUser(username, password, email, phonenumber);
        if (success) { //Código para forçar validação do telefone/email
            System.out.println("Usuário Criado.");
            System.out.println("Código de validação do telefone: ");

            String code = scanner.nextLine();
            helper.verifyAccessCode(username, code);
            System.out.println("Verificação do Usuário Completa.");
        } else {
            System.out.println("Criação do Usuário deu Ruim.");
        }
    }

    private static void validateUser(CognitoHelper helper) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Username: ");
        String username = scanner.nextLine();

        System.out.println("Password: ");
        String password = scanner.nextLine();

        String result = helper.validateUser(username, password);
        if (result != null) {
            System.out.println("Usuário Autenticado: " + result);
        } else {
            System.out.println("Username/Password errado");
        }

        JSONObject payload = CognitoJWTParser.getPayload(result);
        String provider = payload.get("iss").toString().replace("https://", "");

        System.out.println("payload " + payload + "\n provider " + provider);
    }


    private static void resetPassword(CognitoHelper helper) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Usuário: ");
        String username = scanner.nextLine();

        String result = helper.resetPassword(username);
        if (result != null) {
            System.out.println("Código reset da senha: " + result);
        } else {
            System.out.println("Mudança de senha deu ruim.");
            System.exit(1);
        }

        System.out.println("Código reset da senha: ");
        String code = scanner.nextLine();

        System.out.println("Novo password confirmado: ");
        String password = scanner.nextLine();

        String confirmation = helper.updatePassword(username, password, code);
        if (confirmation != null) {
            System.out.println("Mudança de senha confirmada: " + confirmation);
        } else {
            System.out.println("Mudança de senha deu ruim.");
            System.exit(1);
        }

    }
}
