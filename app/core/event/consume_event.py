from core.helper.consumer_helper import consume_event
from core.utils.settings import settings
from core.utils.init_log import logger
from core.helper.token_helper import AssignToken, assign_token, ReusedToken, RevokeToken, invalidate_account_tokens, send_threat_notification, update_refresh_token, UpdateToken, revoke_refresh_token

# Processing event msg
event_processing_msg = "Processing event"


async def consume_assign_token_event():
    # consume event
    consumer = await consume_event(topic=settings.api_assign_token, group_id=settings.api_assign_token)
    
    try:
        # Consume messages
        async for msg in consumer: 
            logger.info('Received assign token event.') 
            # Deserialize event
            assign_token_data = AssignToken.deserialize(data=msg.value)
            
            # Assign token
            logger.info(event_processing_msg)
            await assign_token(data = assign_token_data)
    except Exception as err:
        logger.error(f'Failed to process event due to error: {str(err)}')
    finally:
        await consumer.stop()


async def consume_reused_refresh_token_event():
    # consume event
    consumer = await consume_event(topic=settings.api_reused_refresh_token, group_id=settings.api_reused_refresh_token)
    
    try:
        # Consume messages
        async for msg in consumer: 
            logger.info('Received reused refresh token event.') 
            
            # Deserialize event
            account_data = ReusedToken.deserialize(data=msg.value)
            
            # invalidate token
            logger.info(event_processing_msg)
            await invalidate_account_tokens(id=account_data.id)
            
            # Notify account owner of threat
            await send_threat_notification(id=account_data.id)
    except Exception as err:
        logger.error(f'Failed to process event due to error: {str(err)}')
    finally:
        await consumer.stop()


async def consume_update_token_event():
    # consume event
    consumer = await consume_event(topic=settings.api_update_token, group_id=settings.api_update_token)
    
    try:
        # Consume messages
        async for msg in consumer: 
            logger.info('Received update refresh token event.') 
            
            # Deserialize event
            update_token_data = UpdateToken.deserialize(data=msg.value)
            
            # update token
            logger.info(event_processing_msg)
            await update_refresh_token(data=update_token_data)
    except Exception as err:
        logger.error(f'Failed to process event due to error: {str(err)}')
    finally:
        await consumer.stop()


async def consume_revoke_token_event():
    # consume event
    consumer = await consume_event(topic=settings.api_revoke_refresh_token, group_id=settings.api_revoke_refresh_token)
    
    try:
        # Consume messages
        async for msg in consumer: 
            logger.info('Received revoke refresh token event.') 
            
            # Deserialize event
            revoke_token_data = RevokeToken.deserialize(data=msg.value)
            
            # revoke token
            logger.info(event_processing_msg)
            await revoke_refresh_token(data=revoke_token_data)
    except Exception as err:
        logger.error(f'Failed to process event due to error: {str(err)}')
    finally:
        await consumer.stop()
