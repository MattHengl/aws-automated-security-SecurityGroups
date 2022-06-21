/*!
     * Copyright 2017-2017 Mutual of Enumclaw. All Rights Reserved.
     * License: Public
*/ 

//Mutual of Enumclaw 
//
//Matthew Hengl and Jocelyn Borovich - 2019 :) :)
//
//Main file that controls remediation and notifications of all EC2 Security Group events. 
//Remediates actions when possible or necessary based on launch type and tagging. Then, notifies the user/security. 

//Make sure to that the master.invalid call does NOT have a ! infront of it
//Make sure to delete or comment out the change in the process.env.environtment

const AWS = require('aws-sdk');
AWS.config.update({region: process.env.region});
const ec2 = new AWS.EC2();
const Master = require("aws-automated-master-class/MasterClass").handler;
let path = require("aws-automated-master-class/MasterClass").path;
const master = new Master();

let callRemediate = remediate;
let callOverride = overrideFunction;
let callOverride2 = overrideFunction2;

//Only used for testing purposes
setEc2Function = (value, funct) => {
    ec2[value] = funct;
};

async function handleEvent(event){

    console.log(process.env.environment);

    let resourceName = 'groupId';
    console.log(JSON.stringify(event));
    path.p = 'Path: \nEntered handleEvent';


    event = master.devTest(event);
    //Checks if there is an error in the log
    if (master.errorInLog(event)) {
        console.log(path.p);
        return; 
    }

    //Checks if the log came from this function, quits the program if it does.
    if (master.selfInvoked(event)) {
        console.log(path.p);
        return;
    }

    console.log(`Event action is ${event.detail.eventName}------------------------`);

    if(event.detail.eventName == 'CreateSecurityGroup'){
        resourceName = 'groupName';
    }

    //if(master.checkKeyUser(event, resourceName)){
        //change this for when you're not testing in snd.
        if(master.invalid(event)){
            try{
                await master.notifyUser(event, await callRemediate(event), 'Security Group');
            }
            catch(e){
                console.log(e);
                path.p += '\nERROR';
                console.log(path.p);
                delete path.p;
                return e;
            }
        }   
    //}
    console.log(path.p);
    delete path.p;
}
async function remediate(event){

    path.p += '\nEntered the remediation function';

    const erp = event.detail.requestParameters;
    const ere = event.detail.responseElements;

    let params = {GroupId: erp.groupId};
    let results = master.getResults(event, {ResourceName: params.GroupId});

    try{
        switch(results.Action){
            //done?
            case 'AuthorizeSecurityGroupEgress':
                path.p += '\nAuthorizeSecurityGroupEgress';
                //What the next couple of lines are creating a map. The "key" values are te element, which is an object.
                //The "value" is the function that is being called to manipulate the info in that object
                callOverride2(event, 'revokeSecurityGroupEgress');
                results.Response = 'RevokeSecurityGroupEgress';
            break;
            //done?
            case 'RevokeSecurityGroupEgress':
                path.p += '\nRevokeSecurityGroupEgress';
                callOverride2(event, 'authorizeSecurityGroupEgress');
                results.Response = 'AuthorizeSecurityGroupEgress';
            break;
            //done
            case 'AuthorizeSecurityGroupIngress':
                path.p += '\nAuthorizeSecurityGroupIngress';
                callOverride2(event, 'revokeSecurityGroupIngress');
                results.Response = 'RevokeSecurityGroupIngress';
            break;
            //done
            case 'RevokeSecurityGroupIngress':
                path.p += '\nRevokeSecurityGroupIngress';
                callOverride2(event, 'authorizeSecurityGroupIngress');
                results.Response = 'AuthorizeSecurityGroupIngress';
            break;
            //done
            case 'CreateSecurityGroup':
                path.p += '\nCreateSecurityGroup';
                params.GroupId = ere.groupId;
                await callOverride('deleteSecurityGroup', params);
                results.Resource = ere.groupId;
                results.Response = 'DeleteSecurityGroup';
            break;
            //done
            case 'DeleteSecurityGroup':
                path.p += '\nDeleteSecurityGroup';
                results.Response = 'Remediation could not be performed';
            break;
        }
    }
    catch(e){
        //stopper.id = id;
        console.log(e);
        path.p += '\nERROR';
        return e;
    }
    results.Reason = `Improper Launch`;
    if(results.Response == "Remediation could not be performed"){
       delete results.Reason;
    }
    path.p += '\nRemediation was finished, notifying user now';
    return results;
}

function paramsBuilder(event, element){


    let params = {};
    params.GroupId = event.detail.requestParameters.groupId;

    if(element.groups && element.groups.hasOwnProperty('items')){
        params.IpPermissions = [{
            FromPort: element.fromPort,
            ToPort: element.toPort,
            IpProtocol: element.ipProtocol,
            UserIdGroupPairs: [{GroupId: element.groups.items[0].groupId}]
        }];
    }else if(element.ipRanges.hasOwnProperty('items')){
        params.IpPermissions = [{
            FromPort: element.fromPort,
            ToPort: element.toPort,
            IpProtocol: element.ipProtocol,
            IpRanges: [{
                CidrIp: element.ipRanges.items[0].cidrIp
            }]
        }];
    }
    //console.log('Params' + JSON.stringify(params));
    return params;
};

async function overrideFunction(apiFunction, params){
    try{
        if(process.env.run == 'false'){
          await setEc2Function(apiFunction, (params) => {
            console.log(`Overriding ${apiFunction}`);
            return {promise: () => {}};
          });
        }
        await ec2[apiFunction](params).promise();  
    }catch(e){
        //stopper.id = id;
        console.log(e);
        path.p += '\nERROR';
        return e;
    }
};

async function overrideFunction2(event, apiFunction){
    try{
        if(process.env.run == 'false'){
            await setEc2Function(apiFunction, (params) => {
                console.log('Overriding revokeSecurityGroupIngress');
                return {promise: () => {}};
            });
        }
        await Promise.all(event.detail.requestParameters.ipPermissions.items.map(element => 
            ec2[apiFunction](paramsBuilder(event, element)).promise()));
    }catch(e){
        //stopper.id = id;
        console.log(e);
        path.p += '\nERROR';
        return e;
    }
};


exports.handler = handleEvent;
exports.remediate = remediate;

exports.setEc2Function = (value, funct) => {
    ec2[value] = funct;
};
exports.setOverride = (funct) => {
    callOverride = funct;
};
exports.setOverride2 = (funct) => {
    callOverride2 = funct;
};

exports.setRemediate = (funct) => {
    callRemediate = funct;
};