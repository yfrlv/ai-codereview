package artclients.keycloak.authenticator;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;


public class EmailAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(EmailAuthenticator.class);

    private enum CODE_STATUS {
        VALID,
        INVALID,
        EXPIRED
    }

    public void authenticate(AuthenticationFlowContext context) {
        logger.info("authenticate called ... context = " + Collections.singletonList(context.getAuthenticatorConfig().getConfig()));

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();

        String emailAddressAttribute = EmailAuthenticatorUtil.getConfigString(config, EmailAuthenticatorConstants.CONF_PRP_USR_ATTR_EMAIL);

        //запрещает доступ всем у кого нет роли "all clients role"
        List<RoleModel> roles = context.getUser().getRoleMappingsStream()
                .filter(roleModel -> roleModel.getName().equals("all clients role"))
                .collect(Collectors.toList());
        logger.info("user role size: " + roles.size());
        if (roles.isEmpty()) {
            Response challenge = challenge(context, "Error: Access Deny.", null);
            context.failureChallenge(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED, challenge);
        }

        logger.info("user: " + context.getUser());
        logger.info("email address attribute: " + emailAddressAttribute);
        // TODO: 11.12.2023 добавить валидацию email.
        //  Проверку на формат и проверку на существование. Отправлять тестовое письмо,
        //  либо на этапе регистрации юзера проводить обязательную верификацию email
        String email = EmailAuthenticatorUtil.getAttributeValue(context.getUser(), emailAddressAttribute);
        logger.info("email value: " + email);
        if (email != null) {
            long nrOfDigits = EmailAuthenticatorUtil.getConfigLong(config, EmailAuthenticatorConstants.CONF_PRP_OTP_CODE_LENGTH, 8L);
            logger.info("Using nrOfDigits " + nrOfDigits);

            long ttl = EmailAuthenticatorUtil.getConfigLong(config, EmailAuthenticatorConstants.CONF_PRP_OTP_CODE_TTL, 10 * 60L); // 10 minutes in s
            logger.info("Using ttl " + ttl + " (s)");

            String code = getOtpCode(nrOfDigits);

            storeOtpCode(context, code, new Date().getTime() + (ttl * 1000)); // s --> ms
            if (sendOtpCode(email, code, context.getAuthenticatorConfig(), context)) {
                // TODO: 08.12.2023 заменить на адекватную форму
                Response challengeResponse = challenge(context, null, null);
                context.challenge(challengeResponse);
                logger.info("Sent message");
            } else {
                Response challenge = challenge(context, "Error: message could not be sent.", null);
                // TODO: 08.12.2023 заменить на адекватную форму
                context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
                logger.info("Message could not be sent");
            }
        } else {
            // The email is NOT configured
            // TODO: 08.12.2023 заменить на адекватную форму
            Response challenge = challenge(context, "Error: Missing email address.", null);
            context.failureChallenge(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED, challenge);
            logger.info("Missing email address");
        }
    }

    public void action(AuthenticationFlowContext context) {
        logger.info("action called ... context = " + context);
        CODE_STATUS status = validateCode(context);
        Response challenge = null;
        switch (status) {
            case EXPIRED:
                // TODO: 08.12.2023 заменить на адекватную форму
                challenge = challenge(context, "Error: code is expired", "code is expired");
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
                break;
            case INVALID:
                if (context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.ALTERNATIVE) {
                    logger.info("Calling context.attempted()");
                    context.attempted();
                } else if (context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.REQUIRED) {
                    // TODO: 08.12.2023 заменить на адекватную форму
                    challenge = challenge(context, "Error: invalid code", "invalid code");
                    context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
                } else {
                    // Something strange happened
                    logger.info("Undefined execution ...");
                }
                break;
            case VALID:
                context.success();
                break;

        }
    }

    // Store the code + expiration time. Keycloak will persist these in the DB.
    // When the code is validated on another node (in a clustered environment) the other nodes have access to it's values too.
    private void storeOtpCode(AuthenticationFlowContext context, String code, Long expiringAt) {
        CredentialModel credentials = new CredentialModel();
        credentials.setType(EmailAuthenticatorConstants.USR_CRED_MDL_OTP_CODE);
        credentials.setValue(code);

        logger.info("credentials: credentials.getCredentialId() - " + credentials.getId());
        logger.info("credentials: credentials.getType() - " + credentials.getType());
        logger.info("credentials: credentials.getValue() - " + credentials.getValue());

        List<CredentialModel> credentialModelList =
                context.getUser().credentialManager().getStoredCredentialsStream()
                        .filter(credentialModel -> credentialModel.getType().equals(EmailAuthenticatorConstants.USR_CRED_MDL_OTP_CODE))
                        .collect(Collectors.toList());
        credentialModelList.forEach((item) -> {
            logger.info("credentialModelList: " + item.getType() + item.getValue());
        });
        if (credentialModelList.isEmpty()) {
            context.getUser().credentialManager().createStoredCredential(credentials);
            logger.info("create credential flow - " + credentials.getValue());
        } else {
            CredentialModel credentialModelToUpdate = credentialModelList.get(0);
            credentialModelToUpdate.setValue(code);
            context.getUser().credentialManager().updateStoredCredential(credentialModelToUpdate);
            logger.info("update credential flow - " + credentialModelToUpdate.getValue());
        }

        credentials.setType(EmailAuthenticatorConstants.USR_CRED_MDL_OTP_EXP_TIME);
        credentials.setValue((expiringAt).toString());

        logger.info("credentials: credentials.getCredentialId() - " + credentials.getId());
        logger.info("credentials: credentials.getType() - " + credentials.getType());
        logger.info("credentials: credentials.getValue() - " + credentials.getValue());

        List<CredentialModel> credentialModelExpiringList =
                context.getUser().credentialManager().getStoredCredentialsStream()
                        .filter(credentialModel -> credentialModel.getType().equals(EmailAuthenticatorConstants.USR_CRED_MDL_OTP_EXP_TIME))
                        .collect(Collectors.toList());
        credentialModelExpiringList.forEach((item) -> {
            logger.info("credentialModelExpiringList: " + item.getType() + item.getValue());
        });
        if (credentialModelExpiringList.isEmpty()) {
            context.getUser().credentialManager().createStoredCredential(credentials);
            logger.info("create credential expiring flow - " + credentials.getValue());
        } else {
            CredentialModel credentialModelExpiringToUpdate = credentialModelExpiringList.get(0);
            credentialModelExpiringToUpdate.setValue((expiringAt).toString());
            context.getUser().credentialManager().updateStoredCredential(credentialModelExpiringToUpdate);
            logger.info("update credential expiring flow - " + credentialModelExpiringToUpdate.getValue() + credentialModelExpiringToUpdate.getType());
        }
    }

    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        LoginFormsProvider form = context.form()
                .setExecution(context.getExecution().getId());
        logger.info("context.getExecution() - " + context.getExecution());
        if (error != null) {
            if (field != null) {
                form.addError(new FormMessage(field, error));
            } else {
                form.setError(error);
            }
        }
        return createLoginForm(form);
    }

    protected Response createLoginForm(LoginFormsProvider form) {
        logger.info("created form");
        return form.createLoginTotp();
    }

    protected CODE_STATUS validateCode(AuthenticationFlowContext context) {
        CODE_STATUS result = CODE_STATUS.INVALID;

        logger.info("validateCode called ... ");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logger.info("formData  ... " + formData);
        String enteredCode = formData.getFirst("otp");

        String expectedCode = EmailAuthenticatorUtil.getCredentialValue(context.getUser(), EmailAuthenticatorConstants.USR_CRED_MDL_OTP_CODE);
        String expTimeString = EmailAuthenticatorUtil.getCredentialValue(context.getUser(), EmailAuthenticatorConstants.USR_CRED_MDL_OTP_EXP_TIME);

        logger.info("Expected code = " + expectedCode + "    entered code = " + enteredCode);

        if (expectedCode != null) {
            result = enteredCode.equals(expectedCode) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
            long now = new Date().getTime();

            logger.info("Valid code expires in " + (Long.parseLong(expTimeString) - now) + " ms");
            if (result == CODE_STATUS.VALID) {
                if (Long.parseLong(expTimeString) < now) {
                    logger.info("Code is expired !!");
                    result = CODE_STATUS.EXPIRED;
                }
            }
        }
        logger.info("result : " + result);
        return result;
    }

    public boolean requiresUser() {
        logger.info("requiresUser called ... returning true");
        return true;
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.info("configuredFor called ... session=" + session + ", realm=" + realm + ", user=" + user);
        boolean result = true;
        logger.info("... returning " + result);
        return result;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.info("setRequiredActions called ... session=" + session + ", realm=" + realm + ", user=" + user);
    }

    public void close() {
        logger.info("close called ...");
    }


    private String getOtpCode(long nrOfDigits) {
        if (nrOfDigits < 1) {
            throw new RuntimeException("Nr of digits must be bigger than 0");
        }

        double maxValue = Math.pow(10.0, nrOfDigits); // 10 ^ nrOfDigits;
        Random r = new Random();
        long code = (long) (r.nextFloat() * maxValue);
        return Long.toString(code);
    }

    private boolean sendOtpCode(String email, String code, AuthenticatorConfigModel config, AuthenticationFlowContext context) {
        // Send an email message
        logger.info("Sending " + code + "  to email " + email);
        try {
//            sendEmailWithCode(context, context.getUser(), code);
            logger.info("Sending message");
            logger.info("smtpConfig" + context.getRealm().getSmtpConfig());
            Map<String, String> smtpConfig = context.getRealm().getSmtpConfig();
            EmailSenderProvider emailSender = context.getSession().getProvider(EmailSenderProvider.class);
            emailSender.send(
                    smtpConfig,
                    context.getUser(),
                    "Header of message", "This is text of message",
                    "<html><body><h1>" + "This is your code: " + code + "</h1></body></html>"
            );
            logger.info("Sent message with code: " + code);
        } catch (RuntimeException e) {
            logger.error(e);
            return false;
        } catch (EmailException e) {
            throw new RuntimeException(e);
        }

        return true;
    }
}