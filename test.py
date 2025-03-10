import nmcli
 
def get_routes_ip_ranges():
    try:
        temp_route_ip_ranges:dict[str, str | None] = {}
        for device_information in nmcli.device.show_all():
            interface_name:str | None = device_information.get("GENERAL.DEVICE", None)
            if interface_name is not None:
                ip_v4_route:str | None
                ip_v4_route_string:str | None = device_information.get("IP4.ROUTE[1]", None)
                if ip_v4_route_string is not None:
                    parts = ip_v4_route_string.replace(" " , "").split("dst=", 1)
                    if len(parts) == 2:
                        ip_v4_route = parts[-1].split(",", 1)[0]
                    else:
                        ip_v4_route = None
                temp_route_ip_ranges[interface_name] = ip_v4_route
        return (True, temp_route_ip_ranges, None)
    except Exception as e:
        return (False, None, str(e))
 
res:dict[str, str | None] = get_routes_ip_ranges()
print(res)