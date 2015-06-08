/*******************************************************************************
 *
 * Copyright (c) 2013, 2014 Intel Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * The Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    David Navarro, Intel Corporation - initial API and implementation
 *    Fabien Fleutot - Please refer to git log
 *    Simon Bernard - Please refer to git log
 *    Toby Jaffey - Please refer to git log
 *    Pascal Rieux - Please refer to git log
 *    
 *******************************************************************************/

/*
 Copyright (c) 2013, 2014 Intel Corporation

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 THE POSSIBILITY OF SUCH DAMAGE.

 David Navarro <david.navarro@intel.com>

*/


#include "internals.h"

#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#include <mbed/rtc_api.h>

int lwm2m_gettimeofday(struct timeval *tv, void *p)
{
	time_t t = rtc_read();
	tv->tv_sec = t;
	return 0;
}


char *strdup(const char *s)
{
    char* dup = (char*)malloc(strlen(s) + 1);
    if(dup != NULL)
        strcpy(dup, s);
    return dup; 
}


lwm2m_context_t * lwm2m_init(lwm2m_connect_server_callback_t connectCallback,
                             lwm2m_buffer_send_callback_t bufferSendCallback,
                             void * userData)
{
    lwm2m_context_t * contextP;

    if (NULL == bufferSendCallback)
        return NULL;

#ifdef LWM2M_CLIENT_MODE
    if (NULL == connectCallback)
        return NULL;
#endif

    contextP = (lwm2m_context_t *)lwm2m_malloc(sizeof(lwm2m_context_t));
    if (NULL != contextP)
    {
        memset(contextP, 0, sizeof(lwm2m_context_t));
        contextP->connectCallback = connectCallback;
        contextP->bufferSendCallback = bufferSendCallback;
        contextP->userData = userData;
        srand(time(NULL));
        contextP->nextMID = rand();
    }

    return contextP;
}

#ifdef LWM2M_CLIENT_MODE
void lwm2m_delete_object_list_content(lwm2m_context_t * context,
        bool isBackup,
        bool securityAndServerOnly) {
    lwm2m_object_t ** objectList = isBackup ? context->objectListBackup : context->objectList;
    int objectCount = isBackup ? context->numObjectBackup : context->numObject;
    if (NULL != objectList) {
        int i;
        for (i = 0 ; i < objectCount ; i++) {
            if (NULL != objectList[i]) {
                if (!securityAndServerOnly ||
                        (securityAndServerOnly && ((objectList[i]->objID == 0) || objectList[i]->objID == 1))) {
                    if (NULL != objectList[i]->closeFunc) {
                        objectList[i]->closeFunc(objectList[i]);
                    }
                }
                /*
                 * Let's assume that if we want to delete ALL objects
                 * we need to free objects as well
                 */
                if (!securityAndServerOnly) {
                    lwm2m_free(objectList[i]);
                    objectList[i] = NULL;
                }
            }
        }
    }
}

void lwm2m_deregister(lwm2m_context_t * context) {
    lwm2m_server_t * server = context->serverList;
    while (NULL != server){
        registration_deregister(context, server);
        server = server->next;
    }
}

void delete_server_list(lwm2m_context_t * context) {
    while (NULL != context->serverList){
        lwm2m_server_t * server;
        server = context->serverList;
        context->serverList = context->serverList->next;
        if (NULL != server->location) {
            lwm2m_free(server->location);
        }
        lwm2m_free(server);
        server = NULL;
    }
    lwm2m_free(context->serverList);
    context->serverList = NULL;
}

void delete_bootstrap_server_list(lwm2m_context_t * contextP) {
    if (NULL != contextP->bootstrapServerList) {
        while (NULL != contextP->bootstrapServerList) {
            lwm2m_server_t * targetP;

            targetP = contextP->bootstrapServerList;
            contextP->bootstrapServerList = contextP->bootstrapServerList->next;

            lwm2m_free(targetP);
            targetP = NULL;
        }
        lwm2m_free(contextP->bootstrapServerList);
        contextP->bootstrapServerList = NULL;
    }
}

void delete_observed_list(lwm2m_context_t * contextP) {
    while (NULL != contextP->observedList) {
        lwm2m_observed_t * targetP;

        targetP = contextP->observedList;
        contextP->observedList = contextP->observedList->next;

        while (NULL != targetP->watcherList) {
            lwm2m_watcher_t * watcherP;

            watcherP = targetP->watcherList;
            targetP->watcherList = targetP->watcherList->next;
            lwm2m_free(watcherP);
            watcherP = NULL;
        }
        lwm2m_free(targetP);
        targetP = NULL;
    }
}
#endif

void delete_transaction_list(lwm2m_context_t * context) {
    while (NULL != context->transactionList) {
        lwm2m_transaction_t * transaction;

        transaction = context->transactionList;
        context->transactionList = context->transactionList->next;
        transaction_free(transaction);
    }
}

void lwm2m_close(lwm2m_context_t * contextP)
{
    int i;

#ifdef LWM2M_CLIENT_MODE

    lwm2m_deregister(contextP);
    delete_server_list(contextP);
    delete_bootstrap_server_list(contextP);

    delete_observed_list(contextP);

    lwm2m_delete_object_list_content(contextP, false, false);
    lwm2m_free(contextP->objectList);
    lwm2m_delete_object_list_content(contextP, true, false);
    lwm2m_free(contextP->objectListBackup);

    lwm2m_free(contextP->endpointName);
#endif

#ifdef LWM2M_SERVER_MODE
    while (NULL != contextP->clientList)
    {
        lwm2m_client_t * clientP;

        clientP = contextP->clientList;
        contextP->clientList = contextP->clientList->next;

        prv_freeClient(clientP);
    }
#endif

    delete_transaction_list(contextP);
    lwm2m_free(contextP);
}

#ifdef LWM2M_CLIENT_MODE
int lwm2m_configure(lwm2m_context_t * contextP,
                    char * endpointName,
                    char * msisdn,
                    uint16_t numObject,
                    lwm2m_object_t * objectList[])
{
    int i;
    uint8_t found;

    // This API can be called only once for now
    if (contextP->endpointName != NULL) return COAP_400_BAD_REQUEST;

    if (endpointName == NULL) return COAP_400_BAD_REQUEST;
    if (numObject < 3) return COAP_400_BAD_REQUEST;
    // Check that mandatory objects are present
    found = 0;
    for (i = 0 ; i < numObject ; i++)
    {
        if (objectList[i]->objID == LWM2M_SECURITY_OBJECT_ID) found |= 0x01;
        if (objectList[i]->objID == LWM2M_SERVER_OBJECT_ID) found |= 0x02;
        if (objectList[i]->objID == LWM2M_DEVICE_OBJECT_ID) found |= 0x04;
    }
    if (found != 0x07) return COAP_400_BAD_REQUEST;

    contextP->endpointName = strdup(endpointName);
    if (contextP->endpointName == NULL)
    {
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    if (msisdn != NULL)
    {
        contextP->msisdn = strdup(msisdn);
        if (contextP->msisdn == NULL)
        {
            return COAP_500_INTERNAL_SERVER_ERROR;
        }
    }

    contextP->objectList = (lwm2m_object_t **)lwm2m_malloc(numObject * sizeof(lwm2m_object_t *));
    if (NULL != contextP->objectList)
    {
        memcpy(contextP->objectList, objectList, numObject * sizeof(lwm2m_object_t *));
        contextP->numObject = numObject;
    }
    else
    {
        lwm2m_free(contextP->endpointName);
        contextP->endpointName = NULL;
        return COAP_500_INTERNAL_SERVER_ERROR;
    }
    contextP->objectListBackup = NULL;
    return COAP_NO_ERROR;
}

void lwm2m_backup_objects(lwm2m_context_t * context)
{
    uint16_t i;
    lwm2m_object_t * objectListBackup[context->numObject];

    if (NULL == context->objectListBackup) {
        context->objectListBackup = (lwm2m_object_t **)lwm2m_malloc(context->numObject * sizeof(lwm2m_object_t *));
        for (i = 0; i < context->numObject; i++) {
            context->objectListBackup[i] = (lwm2m_object_t *)lwm2m_malloc(sizeof(lwm2m_object_t));
            memset(context->objectListBackup[i], 0, sizeof(lwm2m_object_t));
        }
    }

    /*
     * Delete previous backup content of objects 0 (security) and 1 (server)
     */
    lwm2m_delete_object_list_content(context, true, true);

    /*
     * Backup content of objects 0 (security) and 1 (server)
     */
    for (i = 0; i < context->numObject; i++) {
        if ((context->objectList[i]->objID == 0) || (context->objectList[i]->objID == 1)) {
            context->objectList[i]->copyFunc(context->objectListBackup[i], context->objectList[i]);
        }
    }

    context->numObjectBackup = context->numObject;
}

void lwm2m_restore_objects(lwm2m_context_t * context)
{
    uint16_t i;
    lwm2m_object_t * objectList[context->numObjectBackup];

    /*
     * Delete current content of objects 0 (security) and 1 (server)
     */
    lwm2m_delete_object_list_content(context, false, true);

    /*
     * Restore content  of objects 0 (security) and 1 (server)
     */
    for (i = 0; i < context->numObjectBackup; i++) {
        if ((context->objectList[i]->objID == 0) || (context->objectList[i]->objID == 1)) {
            context->objectList[i]->copyFunc(context->objectList[i], context->objectListBackup[i]);
        }
    }

    object_getServers(context);
    LOG("[BOOTSTRAP] ObjectList restored\r\n");
}
#endif


int lwm2m_step(lwm2m_context_t * contextP,
               struct timeval * timeoutP)
{
    lwm2m_transaction_t * transacP;
    struct timeval currentTime;
#ifdef LWM2M_SERVER_MODE
    lwm2m_client_t * clientP;
#endif

    if (0 != lwm2m_gettimeofday(&currentTime, NULL)) return COAP_500_INTERNAL_SERVER_ERROR;

    transacP = contextP->transactionList;
    while (transacP != NULL)
    {
        // transaction_send() may remove transaction from the linked list
        lwm2m_transaction_t * nextP = transacP->next;
        int removed = 0;

        if (transacP->retrans_time <= currentTime.tv_sec)
        {
            removed = transaction_send(contextP, transacP);
        }

        if (0 == removed)
        {
            time_t interval;

            if (transacP->retrans_time > currentTime.tv_sec)
            {
                interval = transacP->retrans_time - currentTime.tv_sec;
            }
            else
            {
                interval = 1;
            }

            if (timeoutP->tv_sec > interval)
            {
                timeoutP->tv_sec = interval;
            }
        }

        transacP = nextP;
    }
#ifdef LWM2M_CLIENT_MODE
    if ((contextP->bsState != BOOTSTRAP_CLIENT_HOLD_OFF) && (contextP->bsState != BOOTSTRAP_PENDING)) {
        lwm2m_update_registrations(contextP, currentTime.tv_sec, timeoutP);
    }
    lwm2m_update_bootstrap_state(contextP, currentTime.tv_sec, timeoutP);
#endif

#ifdef LWM2M_SERVER_MODE
    // monitor clients lifetime
    clientP = contextP->clientList;
    while (clientP != NULL)
    {
        lwm2m_client_t * nextP = clientP->next;

        if (clientP->endOfLife <= currentTime.tv_sec)
        {
            contextP->clientList = (lwm2m_client_t *)LWM2M_LIST_RM(contextP->clientList, clientP->internalID, NULL);
            if (contextP->monitorCallback != NULL)
            {
                contextP->monitorCallback(clientP->internalID, NULL, DELETED_2_02, NULL, 0, contextP->monitorUserData);
            }
            prv_freeClient(clientP);
        }
        else
        {
            time_t interval;

            interval = clientP->endOfLife - currentTime.tv_sec;

            if (timeoutP->tv_sec > interval)
            {
                timeoutP->tv_sec = interval;
            }
        }
        clientP = nextP;
    }
#endif

    return 0;
}

