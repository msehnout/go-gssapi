#include <gssapi.h>
#include <stdio.h>
#include <string.h>

#include "krb.h"

void DoSth()
{
    goLog("ahoj from DoSth");
}

void report_error(OM_uint32 maj_stat, OM_uint32 min_stat)
{
    OM_uint32 message_context;
    OM_uint32 status_code;
    OM_uint32 maj_status;
    OM_uint32 min_status;
    gss_buffer_desc status_string;

    const size_t PRINTER_SIZE = 1000;
    char *printer = (char *)malloc(PRINTER_SIZE);

    message_context = 0;

    do
    {
        maj_status = gss_display_status(
            &min_status,
            status_code,
            GSS_C_GSS_CODE,
            GSS_C_NO_OID,
            &message_context,
            &status_string);

        snprintf(printer, PRINTER_SIZE, "%.*s\n", (int)status_string.length, (char *)status_string.value);
        goLog(printer);
        memset((void *)printer, 0, status_string.length);
        gss_release_buffer(&min_status, &status_string);

    } while (message_context != 0);
}

int requestAuthenticated(void *input_buffer, size_t len)
{
    OM_uint32 maj_stat, min_stat, time_rec;
    gss_ctx_id_t context_hdl = GSS_C_NO_CONTEXT;
    gss_cred_id_t cred_hdl = GSS_C_NO_CREDENTIAL, deleg_cred = GSS_C_NO_CREDENTIAL;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_OID mech_type = GSS_C_NO_OID;
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER, display = GSS_C_EMPTY_BUFFER;
    unsigned int ret_flags;

    gss_buffer_desc input_token = {
        .value = input_buffer,
        .length = len,
    };

    const size_t PRINTER_SIZE = 1000;
    char *printer = (char *)malloc(PRINTER_SIZE);
    snprintf(printer, PRINTER_SIZE, "Pointer %p, size %zd", input_buffer, len);
    goLog(printer);

    do
    {
        goLog("Running loop");
        maj_stat = gss_accept_sec_context(&min_stat,
                                          &context_hdl,
                                          cred_hdl,
                                          &input_token,
                                          GSS_C_NO_CHANNEL_BINDINGS,
                                          &client_name,
                                          &mech_type,
                                          &output,
                                          &ret_flags,
                                          &time_rec,
                                          &deleg_cred);
        if (GSS_ERROR(maj_stat))
        {
            report_error(maj_stat, min_stat);
        };
        if (output.length != 0)
        {
            //send_token_to_peer(output_token);
            goLog("I'd like to send a token to the peer. Please implement it!");
            gss_release_buffer(&min_stat, &output);
        };
        if (GSS_ERROR(maj_stat))
        {
            if (context_hdl != GSS_C_NO_CONTEXT)
                gss_delete_sec_context(&min_stat,
                                       &context_hdl,
                                       GSS_C_NO_BUFFER);
            break;
        };
    } while (maj_stat & GSS_S_CONTINUE_NEEDED);

    maj_stat = gss_display_name(&min_stat, client_name, &display, NULL);
    if (GSS_ERROR(maj_stat))
    {
        goLog("gss_display_name");
    }
    snprintf(printer, PRINTER_SIZE, "%s", display.value);
    goLog(printer);


    return 200;
}
