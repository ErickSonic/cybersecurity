package com.ciberseguridad.api.service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class NmapScanningScriptService extends ScanningScriptService{
	
	public Object[] processTCPPortScript(String script) throws IOException{
		ProcessBuilder processBuilder = new ProcessBuilder();
		
		//processBuilder.command("cmd.exe", "/c", script);
	    processBuilder.command("bash", "-c", script);
	
	    try {
	
	        Process process = processBuilder.start();
	
	        Object[] results = new Object[2];
	        List<HashMap<String,String>> ports = new ArrayList<HashMap<String,String>>();
	        HashMap<String,String> map = new HashMap<String, String>();
	        StringBuilder output = new StringBuilder();
	
	        BufferedReader reader = new BufferedReader(
	                new InputStreamReader(process.getInputStream()));
	
	        String line;
	        while ((line = reader.readLine()) != null) {
	        	output.append(line + "\n");
	        	if(line.contains("/tcp")) {
	        		String featuresArr[] = line.split(" ");
	        		int iter = 0;
	        		String versionFeatures = "";
	        		boolean version = false;
	        		for(int i = 0; i < featuresArr.length; i++) {
	        			if(!(featuresArr[i] == "")) {
	        				switch(iter) {
	        					case 0:{
	        						map.put("port", featuresArr[i]);
	        						iter++;
	        						break;
	        					}
	        					case 1:{
	        						map.put("state", featuresArr[i]);
	        						iter++;
	        						break;
	        					}
	        					case 2:{
	        						map.put("service", featuresArr[i]);
	        						iter++;
	        						break;
	        					}
	        					case 3:{
	        						versionFeatures += featuresArr[i];
	        						iter++;
	        						version = true;
	        						break;
	        					}
	        					case 4:{
	        						versionFeatures += " " + featuresArr[i];
	        						break;
	        					}
	        				}
	        			}
	        		}
	        		if(version) {
	        			map.put("version", versionFeatures);
	        		}
	        		ports.add(map);
	        		map = new HashMap<String, String>();
	        	}
	        }
	        results[0] = output.toString();
	        results[1] = ports;
	        return results;
	
	    } catch (IOException e) {
	        e.printStackTrace();
	        throw e;
	    }
	}
	
	public Object[] processVulnerabilitiesScript(String script) throws IOException{
		ProcessBuilder processBuilder = new ProcessBuilder();
		
		//processBuilder.command("cmd.exe", "/c", script);
	    processBuilder.command("bash", "-c", script);
	
	    try {
	
	        Process process = processBuilder.start();
	
	        Object[] results = new Object[2];
	        HashMap<String,List<HashMap<String,String>>> vulnerabilities = new HashMap<String,List<HashMap<String,String>>>();
	        List<HashMap<String,String>> list = new ArrayList<HashMap<String,String>>();
	        HashMap<String,String> map = new HashMap<String, String>();
	        StringBuilder output = new StringBuilder();
	        String portId = "";
	        double globalAverage = 0.0;
	        double localAverage = 0.0;
	        int globalCount = 0;
	        int localCount = 0;
	
	        BufferedReader reader = new BufferedReader(
	                new InputStreamReader(process.getInputStream()));
	
	        String line;
	        while ((line = reader.readLine()) != null) {
	        	output.append(line + "\n");
	        	if(line.contains("CVE-") && line.contains("https://vulners.com/cve")) {
	        		line = line.substring(line.indexOf("CVE-"),line.indexOf("https://vulners.com/cve"));
	        		@SuppressWarnings("deprecation")
					String substrings[] = line.split(new Character((char) 9).toString());
					map.put("id", substrings[0]);
					map.put("evaluation", substrings[1]);
					globalAverage += Double.parseDouble(substrings[1]); localAverage += Double.parseDouble(substrings[1]); globalCount++; localCount++;
					list.add(map);
					map = new HashMap<String, String>();
	        	}
	        	else if(line.contains("CVE:")) {
	        		String substring = line.substring(line.indexOf("CVE:"),line.length()-1);
	        		if(substring.indexOf(" ") != -1) {
	        			substring = substring.substring(3,substring.indexOf(" "));
	        		}
	        		else {
	        			substring = substring.substring(3,substring.length()-1);
	        		}
	        		map.put("id", substring);
	        		if((line = reader.readLine()).contains("Risk factor")) {
	        			line = line.replaceAll("[^0-9.]", "");
	        			map.put("evaluation",line);
	        			globalAverage += Double.parseDouble(line); localAverage += Double.parseDouble(line); globalCount++; localCount++;
	        		}
	        		output.append(line + "\n");
	        		list.add(map);
	        		map = new HashMap<String, String>();
	        	}
	        	else if(line.contains("/tcp")) {
					if (!(portId.equals("")) && !(list.isEmpty())) {
						map.put("average", Double.toString(localAverage / (double) localCount));
						localAverage = 0.0; localCount = 0;
						list.add(map);
						vulnerabilities.put(portId, list);
						list = new ArrayList<HashMap<String, String>>();
						map = new HashMap<String, String>();
						portId = line.split(" ")[0];
					} else {
						portId = line.split(" ")[0];
					}
	        	}
	        }
	        list = new ArrayList<HashMap<String, String>>();
	        map.put("average", Double.toString(globalAverage / (double) globalCount));
	        list.add(map);
	        vulnerabilities.put("average", list);
	        results[0] = output.toString();
	        results[1] = vulnerabilities;
	        return results;
	
	    } catch (IOException e) {
	        e.printStackTrace();
	        throw e;
	    }
	}
	
	
}
