import express, { Request, Response } from 'express';
import crypto from 'crypto';
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { ReclaimClient } from '@reclaimprotocol/zk-fetch';
import { Reclaim } from '@reclaimprotocol/js-sdk';
import dotenv from 'dotenv';
dotenv.config();

const reclaimClient = new ReclaimClient(process.env.APP_ID!, process.env.APP_SECRET!, true);
const app = express();

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.json());

const API_KEY = process.env.BINANCE_API_KEY!;
const API_SECRET = process.env.BINANCE_API_SECRET!;


type Success<T> = {
  success: true;
  data: T;
};

type Failure = {
  success: false;
  error: string;
};

type Result<T> = Success<T> | Failure;


const cacheDir = path.join(__dirname, 'cache');

if (!fs.existsSync(cacheDir)) {
  fs.mkdirSync(cacheDir);
}

const generateCacheKey = (apiKey: string, symbol: string, orderId: string) => {
  const query = "" + apiKey + symbol + orderId;
  return crypto.createHash('md5').update(query).digest('hex') + '.json';
};

const readCache = (cacheFile: string) => {
  const filePath = path.join(cacheDir, cacheFile);
  if (fs.existsSync(filePath)) {
    const data = fs.readFileSync(filePath);
    return JSON.parse(data.toString());
  }
  return null;
};

const writeCache = (cacheFile: string, data: any) => {
  const filePath = path.join(cacheDir, cacheFile);
  fs.writeFileSync(filePath, JSON.stringify({
    data,
    cachedAt: Date.now()
  }));
};

// Function to create a HMAC SHA256 signature
function createSignature(queryString: string, secret: string) {
  return crypto.createHmac('sha256', secret).update(queryString).digest('hex');
}

async function generateProof(url: string, matches: { type: "regex" | "contains"; value: string; }[], apiKey: string): Promise<Result<any>> {
  try{
    const proof = await reclaimClient.zkFetch(url, {
      method: 'GET',
    }, {
      headers : {
        'X-MBX-APIKEY': apiKey
      },
      responseMatches: matches
    },
    3, 5000
  );
  
    if(!proof) {
      return {
        success: false,
        error: "Failed to generate proof"
      }
    }

    const isValid = await Reclaim.verifySignedProof(proof);
    if(!isValid) {
      return {
        success: false,
        error: "Proof is invalid"
      }
    }

    const proofData = await Reclaim.transformForOnchain(proof);
  
    return {
      success: true,
      data: { transformedProof: proofData, proof }
    };
  }
  catch(err){
    let errorMessage: string;
    console.log(err);
    if (err instanceof Error) {
      errorMessage = err.message;
    } else {
      errorMessage = String(err);
    }

    return {
      success: false,
      error: errorMessage
    }
  }
}

async function generateProofWithoutContext(url: string, apiKey: string): Promise<Result<any>> {
  try{
    const proof = await reclaimClient.zkFetch(url, {
      method: 'GET',
    }, {
      headers : {
        'X-MBX-APIKEY': apiKey
      },
    });
  
    if(!proof) {
      return {
        success: false,
        error: "Failed to generate proof"
      }
    }

    const isValid = await Reclaim.verifySignedProof(proof);
    if(!isValid) {
      return {
        success: false,
        error: "Proof is invalid"
      }
    }

    const proofData = await Reclaim.transformForOnchain(proof);
  
    return {
      success: true,
      data: { transformedProof: proofData, proof }
    };
  }
  catch(err){
    let errorMessage: string;
    console.log(err);
    if (err instanceof Error) {
      errorMessage = err.message;
    } else {
      errorMessage = String(err);
    }

    return {
      success: false,
      error: errorMessage
    }
  }
}

app.get('/', async (req: Request, res: Response) => {

  const endpoint = '/fapi/v1/userTrades';
  const serverTimeEndpoint = '/fapi/v1/time';
  let servTime = Date.now();

  try {
    const timeResp = await axios.get(`https://fapi.binance.com${serverTimeEndpoint}`);
    servTime = timeResp.data.serverTime;
 
  } catch (error) {
    return res.status(500).json({ error: error });
  }

  const timestamp = servTime;

  // Query string parameters
  const queryString = `timestamp=${timestamp}&symbol=${req.query.symbol}&recvWindow=60000`;
  const signature = createSignature(queryString, API_SECRET);

  try {
    const response = await axios.get(`https://fapi.binance.com${endpoint}?${queryString}&signature=${signature}`, {
      headers: {
        'X-MBX-APIKEY': API_KEY
      }
    });
    console.log(JSON.stringify(response.data));
    //return res.send(response.data);
    return res.render('trades', { trades: response.data });

  } catch (error) {
    console.log(error);
    return res.status(500).json({ error: error });
  }
});

app.post('/generateUSDMTradeProof', async (req: Request, res: Response) => {

  const cacheKey = generateCacheKey(req.body.api_key, req.body.symbol, req.body.order_id);
  const cache = readCache(cacheKey);

  if (cache) {
    return res.status(200).json(cache.data);
  }
  
  try{
    const endpoint = '/fapi/v1/userTrades';
    const serverTimeEndpoint = '/fapi/v1/time';
    let servTime = Date.now();

    try {
      const timeResp = await axios.get(`https://fapi.binance.com${serverTimeEndpoint}`);
      servTime = timeResp.data.serverTime;
    
    } catch (error) {
      
    }

    const timestamp = servTime;
    const queryString = `timestamp=${timestamp}&symbol=${req.body.symbol}&orderId=${req.body.order_id}&recvWindow=60000`;
    const signature = createSignature(queryString, req.body.api_secret);

    const result = await generateProof(
      `https://fapi.binance.com${endpoint}?${queryString}&signature=${signature}`,
      [
        {
            "type": "regex",
            "value": `"orderId":\\s*(?<orderId>[\\d.]+)`
        }
      ],
      req.body.api_key
    );

    if (!result.success) {
      console.log(result);
      return res.status(400).send(result.error);
    }

    writeCache(cacheKey, result.data);
    
    return res.status(200).json(result.data);
  } catch(e){
      console.log(e);
      return res.status(500).send(e);
  }
})

app.post('/generateAssetProof', async (req: Request, res: Response) => {
  try{
    const endpoint = '/api/v3/account';
    const timestamp = Date.now();
    const queryString = `timestamp=${timestamp}`;
    const signature = createSignature(queryString, req.body.api_secret);

    const result = await generateProof(
      `https://api.binance.com${endpoint}?${queryString}&signature=${signature}`,
      [
        {
            "type": "regex",
            "value": `"asset":\\s*"${req.body.asset}",\\s*"free":\\s*"(?<amount>[\\d.]+)"`
        }
      ],
      req.body.api_key
    );

    if (!result.success) {
      return res.status(400).send(result.error);
    }
    
    return res.status(200).json(result.data);
  } catch(e){
      console.log(e);
      return res.status(500).send(e);
  }
})

app.post('/debugproxy', async (req: Request, res: Response) => {
  try{
    const proof = await reclaimClient.zkFetch("https://browserleaks.com/ip", {
      method: 'GET',
    });
  
    if(!proof) {
      return {
        success: false,
        error: "Failed to generate proof"
      }
    }

    const isValid = await Reclaim.verifySignedProof(proof);
    if(!isValid) {
      return {
        success: false,
        error: "Proof is invalid"
      }
    }

    const proofData = await Reclaim.transformForOnchain(proof);
  
    return {
      success: true,
      data: { transformedProof: proofData, proof }
    };
  }
  catch(err){
    let errorMessage: string;
    console.log(err);
    if (err instanceof Error) {
      errorMessage = err.message;
    } else {
      errorMessage = String(err);
    }

    return {
      success: false,
      error: errorMessage
    }
  }
})


const PORT = process.env.PORT || 8080;

// Start server
app.listen(PORT, () => {
  console.log(`App is listening on port ${PORT}`);
});