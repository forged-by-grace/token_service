from core.model.update_model import *
from core.model.token_models import *
from core.model.notification_avro_model import Notification

from core.enums.token_enum import *
from core.event.produce_event import produce_event

from core.utils.settings import settings
from core.utils.init_log import logger

from core.helper.db_helper import get_account_by_id


async def assign_token(data: AssignToken):
    # Create database field obj
    token_field = UpdateFieldAvro(action='$push', value={'tokens': data.token})
    is_active_field = UpdateFieldAvro(action='$set', value={'is_active': True})
    active_device_count_field = UpdateFieldAvro(action='$inc', value={'active_device_count': 1})
    active_devices_field = UpdateFieldAvro(action='$push', value={'active_devices': data.device_ip})
    role_field = UpdateFieldAvro(action='$set', value={'role.name':  Role.authenticated.value})
    disabled_field = UpdateFieldAvro(action='$set', value={'disabled': False})
    last_update_field = UpdateFieldAvro(action='$set', value={'last_update': datetime.utcnow().isoformat()})

    # Create update list
    account_updates = UpdateAvro(
        db_filter={'_id': data.id},
        updates=[
            token_field, 
            is_active_field, 
            active_device_count_field, 
            active_devices_field, 
            role_field,
            disabled_field, 
            last_update_field
        ]
    )

    # Convert to dict
    device_dict = data.device_info.model_dump()
    
    # Add email to device data
    device_dict.update({'email': data.email})

    # Create new device obj
    new_device = AddDevice(**device_dict)
    new_device_event = new_device.serialize()
    
    logger.info('Emitting add new device event.')
    await produce_event(topic=settings.api_add_device, value=new_device_event)
    
    # Emit update event
    await emit_update_event(account_updates=account_updates)


async def invalidate_account_tokens(id: str) -> None:
    # Create database field objs
    tokens_field = UpdateFieldAvro(action='$set', value={'tokens': []})
    last_update_field = UpdateFieldAvro(action='$set', value={'last_update': datetime.utcnow().isoformat()})
    is_active_field = UpdateFieldAvro(action='$set', value={'is_active': False})
    active_device_count_field = UpdateFieldAvro(action='$set', value={'active_device_count': 0})
    active_devices_field = UpdateFieldAvro(action='$set', value={'active_devices': []})
    role_field = UpdateFieldAvro(action='$set', value={'role.name': Role.anonymouse.value})

    # Create update list
    account_updates = UpdateAvro(
        db_filter={'_id': id},
        updates=[
            tokens_field, 
            is_active_field, 
            active_device_count_field, 
            active_devices_field, 
            role_field, 
            last_update_field
        ]
    )

    # Emit update event
    await emit_update_event(account_updates=account_updates)


async def send_threat_notification(id: str) -> None:
    # Fetching account from database    
    account_data = await get_account_by_id(id=id)

    # Check if account exists
    if account_data: 
        # Recipient name
        name = f"{account_data.get('lastname')}, {account_data.get('firstname')}"
        
        # Create notification obj
        notification = Notification(
            recipient_name=name,
            send_to=account_data.get('email'),
            channel=NotificationChannel.email,
            content={},
            template=NotificationTemplate.reused_token_detected.value
        )

        # Serialize
        notification_event = notification.serialize()

        # Emit event
        await produce_event(topic=settings.api_notification, value=notification_event)


async def update_refresh_token(data: UpdateToken) -> None:
   
    # Create database field objs
    token_field = UpdateFieldAvro(action='$set', value={'tokens.$': data.new_token})
    last_update_field = UpdateFieldAvro(action='$set', value={'last_update': datetime.utcnow().isoformat()})
    
    # Create update list
    account_updates = UpdateAvro(
        db_filter={
            '_id': data.id,
            'tokens': data.old_token
        },
        updates=[
            token_field,
            last_update_field,
        ]
    )

    await emit_update_event(account_updates=account_updates)

   
async def emit_update_event(account_updates: UpdateAvro) -> None:
    # Serialize    
    account_updates_event = account_updates.serialize()

    # Emit event
    logger.info('Emitting update account event')
    await produce_event(topic=settings.api_update_account, value=account_updates_event)


async def revoke_refresh_token(data: RevokeToken) -> None:
    # Create database field objs
    tokens_field = UpdateFieldAvro(action='$pull', value={'tokens': data.token})
    last_update_field = UpdateFieldAvro(action='$set', value={'last_update': datetime.utcnow().isoformat()})
    is_active_field = UpdateFieldAvro(action='$set', value={'is_active': False})
    active_device_count_field = UpdateFieldAvro(action='$set', value={'active_device_account': -1})
    active_devices_field = UpdateFieldAvro(action='$pull', value={'active_devices': data.device_ip})
    role_field = UpdateFieldAvro(action='$set', value={'role': {'name': Role.anonymouse.value}})

    # Create update list
    account_updates = UpdateAvro(
        db_filter={'_id': data.id},
        updates=[
            tokens_field, 
            is_active_field, 
            active_device_count_field, 
            active_devices_field, 
            role_field, 
            last_update_field
        ]
    )

    # Emit update event
    await emit_update_event(account_updates=account_updates)
