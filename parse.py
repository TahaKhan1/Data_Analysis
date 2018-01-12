#Site:Logan Wind Energy, Colarado, USA
#EIA ID: 56613
#FERC.ID: 1881
#COMPARISION OF MODELED AND OBESERVED DATA 

#Author:Taha Khan
#Date:November-13-2017
import csv
import itertools

NUM_TURBINES = 134
NUM_MTHS_NULL = 9   #From 2007_January to 2007_September

time=[]
date=[]
wind_speeds=[]
cnt_wd=0

#Reading the data from WindData.csv and parsing Time and Wind Speeds_50m
#in a list date and wind_speeds. 

with open('WindData.csv') as csvfile:
	wd_reader=csv.reader(csvfile,delimiter=str(u',').encode('utf-8'))
   	for row in wd_reader:
		
		if cnt_wd != 0:
			date_time = row[0].split(' ')
			date.append(date_time[0])
			year = date_time[0].split('-')


			if int(year[0]) >= 2007:
				time.append(row[0])
				wind_speeds.append(row[5])
		
		cnt_wd += 1
	
# round is an index that is used to in rounding of wind_speeds to the nearest factor
#of 0.25m/s.
round=[0.0,0.25,0.5,0.75,1.0]

diff=[]
# cnt is used as a counter while iterating over wind_speeds. 
cnt=0
# following loop is to round off the wind_speed_50m to its nearest factor of 0.25m/s.
for speed in wind_speeds:
	speed_int = int(float(speed))
	speed_dec = float(speed) - speed_int	
	for x in round:
		diff.append(abs(speed_dec - x))
		speed_dec_rnd = round[diff.index(min(diff))]
		speed_rounded = speed_int + speed_dec_rnd
	
	wind_speeds[cnt] = speed_rounded
	diff=[]
	cnt += 1
	
#print wind_speeds

power=[]
energy=[]
cnt_pc=0

# Reading PowerCurve.csv and evaluating the corresponding power(kW) for 
# wind speed in list wind_speeds.
# Line 75: Evaluating the Total Energy produced(MWh) every hour
# by multiplying the energy produced by Number of Turbines at site.

with open('PowerCurve.csv') as csvfile:
	pc_reader=list(csv.reader(csvfile,delimiter=str(u',').encode('utf-8')))
	
	for ws in wind_speeds:
		idx = int(ws / 0.25 + 1)
		power.append(pc_reader[idx][1])	
		energy.append((float(power[cnt_pc]) / 1000.00) * NUM_TURBINES)
		cnt_pc += 1	
#Line:79-104 Evaluating the monthly energy output at site.
energy_monthly=[]
cnt_hr=0
cnt_e =0
curr_mth=1
total_energy=0

for e in energy:

	date_split = date[cnt_e].split('-') # Spliting date and parsing months.
	mth = int(date_split[1])
	
	if mth == curr_mth:
		total_energy += e  ## Summation of total energy for each day of month.
		cnt_hr += 1
	else:
		# appending the total energy to list energy_monthly.
		energy_monthly.append(int(total_energy))
		cnt_hr = 0
		total_energy = 0
		
		if curr_mth == 12:
			curr_mth = 1
		else:
			curr_mth += 1
			
	cnt_e += 1

# According to SiteEnergy.csv observed Power(kW) for first 9 months of 2007 is 0 kW.
# Making the first 9 months of modeled energy to zero.

for i in range (0,9):
	energy_monthly[i] = 0 
	
modeled_energy=[]

for e in energy_monthly:
	modeled_energy.append(int(e))
	

month=[]
observed_energy=[]
total_observed_e=0
avg_observed_e=0
cnt_se=0

with open('SiteEnergy.csv') as csvfile:
	se_reader=list(csv.reader(csvfile,delimiter=str(u',').encode('utf-8')))
	
	for row in se_reader:
	
		if cnt_se != 0:
			month.append(row[0])
			observed_energy.append(int(float(row[1])))
		
		cnt_se += 1
#Calculating average observed energy 		
for i in range(NUM_MTHS_NULL, len(observed_energy)):
	total_observed_e += observed_energy[i]

avg_observed_e = total_observed_e/(len(observed_energy)-NUM_MTHS_NULL)
	
		
e_rows = len(month) + 1
cnt_ec=0


diff_ob_mdl=[]  # difference between observed and modeled energy
abs_diff_ob_mdl=[]  # absolute  difference between observed and modeled energy
diff_per_turbine=[]  # absolute difference per turbine
cnt_diff=0

total_abs_diff=0
avg_diff=0

for i in range(len(observed_energy)):
	diff_ob_mdl.append(observed_energy[cnt_diff]-modeled_energy[cnt_diff])
	abs_diff_ob_mdl.append(abs(observed_energy[cnt_diff]-modeled_energy[cnt_diff]))
	diff_per_turbine.append(abs_diff_ob_mdl[cnt_diff]/NUM_TURBINES)
	cnt_diff += 1

#Evaluating average difference between observed and modeled energy excluding NUM_MTHS_NULL.

for i in range(NUM_MTHS_NULL, len(abs_diff_ob_mdl)):   #excluding NUM_MTHS_NULL
	total_abs_diff += abs_diff_ob_mdl[i]

avg_diff = total_abs_diff/(len(abs_diff_ob_mdl)-NUM_MTHS_NULL) 

# Writing the modeled data in EnergyCompare.csv 
# EnergyCompare.csv include coloums:'Month', 'Observed Energy', 'Modeled Energy'
# 'Diff(between observed and modeled energy), Abs Diff(absolute)
# 'Difference per turbine' (absolute difference/No.of turbines)
with open('EnergyCompare.csv', 'w') as csvfile:
	ec_writer=csv.writer(csvfile,delimiter=str(u',').encode('utf-8'))
	
	for i in range(0,e_rows-1):
		if cnt_ec == 0:
			ec_writer.writerow(['Month','Observed Energy','Modeled Energy','Diff', 'Abs Diff', 'Diff per Turbine'])
		else:
			ec_writer.writerow([month[cnt_ec-1],observed_energy[cnt_ec-1],modeled_energy[cnt_ec-1], 
			diff_ob_mdl[cnt_ec-1], abs_diff_ob_mdl[cnt_ec-1], diff_per_turbine[cnt_ec-1]])
						
		cnt_ec += 1

		
	

		
	
				
	
      
          

	
          
 
