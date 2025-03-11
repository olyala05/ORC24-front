import pymodbus.client.tcp 
 
modbus_address:str = "192.168.1.131:3"
 
(ip_address, slave_id) = modbus_address.split(":", 1)
slave_id = int(slave_id)
 
with pymodbus.client.tcp.ModbusTcpClient(host=ip_address) as connection:
    response = connection.read_holding_registers(
        address=0,
        count=2,
        slave=slave_id
    )
    print(response.registers)
    
    